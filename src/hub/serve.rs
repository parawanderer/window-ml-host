//! serve.rs — `wmlhost hub serve`: the host as a desktop runtime on a hub. Each sealed command that opens and passes
//! the host's own checks is a call of docs/PROTOCOL.md, routed into a session of its own per caller, over the same
//! engine as native messaging (`session::serve`); its answer is sealed back to the caller.
//!
//! The seal opens first, in wmlhub-seal's order (size, HPKE, chain to the account root with leaf == sender,
//! signature, scope held by the leaf, from/to/clock, nonce). Then the host, in this order, each a refusal sealed back
//! that spawns nothing (window-ml's coordinator, 2026-10-19, Q3):
//!
//! 1. the command's scope is `desktop`;
//! 2. the sender is not revoked: the account's revocation list, followed as wmlbox follows it (window-ml-hub
//!    `crates/connector/src/revoked.rs`, used here rather than copied, so the freshness floor is the same one);
//! 3. the sender is in `hub-callers`, read again for every call, so a `wmlhost hub disallow` holds at once.
//!
//! What a session says unprompted (`done`) is a SESSION EVENT, published on a channel of the host's own, one per caller
//! and sealed under a key of that caller's own, granted only to it and only if its leaf holds `view` (Q2). A caller
//! whose presence goes away for [`PRESENCE_GRACE`] has its session closed, so its calls meet their owner-loss policy,
//! and only its calls: each caller's owner table is its own, and so is what dies with it.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use wmlhub_client::{Client, ClientError, Event};
use wmlhub_connector::revoked::{NotNow, Revocations};
use wmlhub_connector::serve::REVOCATIONS_PURPOSE;
use wmlhub_keys::revocation::RevocationError;
use wmlhub_keys::{Identity, hex, scope, verify_chain};
use wmlhub_proto::bytes::Bytes;
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, Error as HubError, Kind, Presence, RevocationList, StreamRef, error::Code};
use wmlhub_seal::{
    ChannelKey, MAX_STREAM_FRAME_BYTES, NONCE_BYTES, Opened, Recipient, Sender, StreamKey, seal_frame, wrap_key,
};

use super::state::State;
use crate::framing;
use crate::session::{self, Host, Transport};

/// The one scope a call to this host is asked under.
pub const SCOPE: &str = scope::DESKTOP;

/// How much a caller's session may have in flight between it and the hub loop, each way.
const SESSION_PIPE_BYTES: usize = 4 << 20;

/// The purpose of the channel a caller's session events travel on; its subject is the caller's principal, and the
/// publisher is this host. A caller names it from the account's channel key as `ChannelKey::channel(EVENTS_PURPOSE,
/// <its own principal>)`.
pub const EVENTS_PURPOSE: &str = "host.events";

/// The purpose of the retained channel that carries a caller's wrapped key for [`EVENTS_PURPOSE`], same subject.
pub const KEYS_PURPOSE: &str = "host.keys";

/// How many counters a write of the mark reserves ahead of the one about to be used (`Serving::lease`).
const COUNTER_LEASE: u64 = 1000;

/// How long a caller's presence may be gone before its session is closed. Chosen, not derived (window-ml's
/// coordinator, 2026-10-19, Q2): long enough for a phone changing networks, short enough that a laptop lid closed on
/// a run does not leave its calls running for long.
pub const PRESENCE_GRACE: Duration = Duration::from_secs(30);

/// Why the host refused a command whose seal opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// it was asked under another scope than `desktop`
    Scope(String),
    /// the account's revocation list names the sender, or a key in its chain
    Revoked,
    /// the list the host holds is older than the freshness floor: the revoker has not been heard from since then
    Stale { since_ms: u64 },
    /// the sender is not in `hub-callers` (or the file could not be read, which refuses everyone)
    NotACaller,
}

impl Refusal {
    /// The `reason` a refusal's error carries, for a caller to branch on.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Scope(_) => "scope",
            Self::Revoked => "revoked",
            Self::Stale { .. } => "stale",
            Self::NotACaller => "notACaller",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Scope(s) => format!("a call to this host is asked under the {SCOPE:?} scope, not {s:?}"),
            Self::Revoked => "the account has revoked this caller".into(),
            Self::Stale { since_ms } => {
                format!(
                    "this host has not heard the account's revocation list since {since_ms}; it refuses until it does"
                )
            }
            Self::NotACaller => {
                "this caller is not allowed here (`wmlhost hub allow <principal>` at this machine)".into()
            }
        }
    }
}

/// The host's own checks on an opened command, in their order. Pure, so each refusal is tested on its own.
pub fn admit(
    opened: &Opened,
    revocations: &Revocations,
    callers: &BTreeSet<[u8; 32]>,
    now_ms: u64,
) -> Result<(), Refusal> {
    if opened.scope != SCOPE {
        return Err(Refusal::Scope(opened.scope.clone()));
    }
    match revocations.may_grant(&opened.chain, now_ms) {
        Ok(()) => {}
        Err(NotNow::Revoked) => return Err(Refusal::Revoked),
        Err(NotNow::Stale { since_ms }) => return Err(Refusal::Stale { since_ms }),
    }
    if !callers.contains(&opened.from) {
        return Err(Refusal::NotACaller);
    }
    Ok(())
}

/// Makes the `Host` a caller's session runs on, given the transport it is to report and bound itself by. Its
/// `owners_dir` is replaced by the caller's own. Each call must give a `Store` of its own, as `Host::from_system`
/// does: one shared by two callers would collide on their calls' temp directories (named by a per-session id) and
/// hold both callers' output where either could `read` it.
pub type MakeHost = dyn Fn(Transport) -> std::io::Result<Host> + Send + Sync;

/// What serving did, for logs and for tests (which assert that a refusal routed nothing).
#[derive(Debug, Default)]
pub struct Counts {
    /// calls handed to a caller's session
    pub routed: AtomicU64,
    /// commands refused by [`admit`]
    pub refused: AtomicU64,
    /// commands whose body was not a call (answered `BadRequest` without reaching a session)
    pub malformed: AtomicU64,
    /// answers sealed back from a session
    pub answered: AtomicU64,
    /// revocation lists applied
    pub lists: AtomicU64,
    /// session events published
    pub events: AtomicU64,
    /// session events published to nobody: the caller holds no `view`, or the event did not fit a frame
    pub unpublished: AtomicU64,
    /// sessions closed because their caller's presence stayed gone past the grace
    pub gone: AtomicU64,
}

/// Who this host signs its published frames and key grants as: what pairing gave it.
pub struct Publisher {
    pub identity: Identity,
    /// leaf first
    pub chain: Vec<Certificate>,
}

/// Why serving stopped.
#[derive(Debug)]
pub enum ServeError {
    /// the hub connection failed, or the hub closed it
    Hub(ClientError),
    /// the hub refused something about this connection (not a throttle)
    Refused(HubError),
    /// who is revoked could not be written down: serving stops rather than forget it on the next start
    State(std::io::Error),
}

/// A command waiting for its session's answer.
struct Asked {
    to: Recipient,
    nonce: [u8; NONCE_BYTES],
    /// the `seq` the caller chose, restored on the answer
    seq: Value,
}

/// A caller's session: where its calls are written.
struct Caller {
    input: WriteHalf<DuplexStream>,
}

/// A caller's event stream: kept for the life of this process, across that caller's sessions, so a counter never
/// repeats under one key.
struct Stream {
    key: StreamKey,
    channel: Vec<u8>,
    counter: u64,
}

/// The host on one hub connection.
pub struct Serving<'a> {
    state: &'a State,
    channel_key: ChannelKey,
    revocations: Revocations,
    /// wmlbox's state type, over the same directory, for the two revocation files only
    revocation_files: wmlhub_connector::State,
    make_host: Arc<MakeHost>,
    publisher: Publisher,
    callers: HashMap<[u8; 32], Caller>,
    /// by caller; absent for a caller whose leaf holds no `view`
    streams: HashMap<[u8; 32], Stream>,
    /// callers whose presence went away, and when their session is closed unless it comes back
    gone: HashMap<[u8; 32], Instant>,
    grace: Duration,
    /// the counter mark as this process found it: every stream starts above it
    floor: u64,
    /// the mark as last written: no frame is sealed with a counter above it
    leased: u64,
    asked: HashMap<u64, Asked>,
    next_seq: u64,
    answers_tx: mpsc::UnboundedSender<([u8; 32], Vec<u8>)>,
    answers_rx: mpsc::UnboundedReceiver<([u8; 32], Vec<u8>)>,
    counts: Arc<Counts>,
    /// what every caller's `hello` reports the revocation list's age from
    revocations_since: Arc<AtomicU64>,
}

impl<'a> Serving<'a> {
    /// `account_root` and `channel_key` are what pairing gave this host (`State::paired`).
    pub fn new(
        state: &'a State,
        account_root: [u8; 32],
        channel_key: ChannelKey,
        publisher: Publisher,
        make_host: Arc<MakeHost>,
    ) -> std::io::Result<Self> {
        let revocation_files = wmlhub_connector::State::at(state.dir());
        let revocations = revocation_files.revocations(&account_root)?;
        let floor = state.counter_mark()?;
        let (answers_tx, answers_rx) = mpsc::unbounded_channel();
        let serving = Self {
            state,
            channel_key,
            revocations,
            revocation_files,
            make_host,
            publisher,
            callers: HashMap::new(),
            streams: HashMap::new(),
            gone: HashMap::new(),
            grace: PRESENCE_GRACE,
            floor,
            leased: floor,
            asked: HashMap::new(),
            next_seq: 1,
            answers_tx,
            answers_rx,
            counts: Arc::default(),
            revocations_since: Arc::default(),
        };
        serving.note();
        Ok(serving)
    }

    /// Publish how fresh the held list is, for `hello`: the same instant `may_grant` measures the floor from.
    fn note(&self) {
        let since = self.revocations.held().map(|h| h.version).or(self.revocations.armed_at()).unwrap_or(0);
        self.revocations_since.store(since, Ordering::Relaxed);
    }

    /// A grace other than [`PRESENCE_GRACE`], for tests.
    pub fn with_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    pub fn counts(&self) -> Arc<Counts> {
        self.counts.clone()
    }

    /// Serve until the hub connection ends. Every caller's session ends with it, so its running calls meet their
    /// owner-loss policy.
    pub async fn run(&mut self, client: &mut Client, now_ms: &impl Fn() -> u64) -> ServeError {
        let revokers: Vec<[u8; 32]> = self.revocations.revokers().copied().collect();
        for revoker in revokers {
            if let Err(e) = self.follow(client, &revoker).await {
                return e;
            }
        }
        loop {
            // `Client::next` is safe to drop (wmlhub-client), and an answer taken off the channel is sent before
            // the next wait, so whichever loses holds nothing.
            let deadline = self.gone.values().min().copied();
            let outcome = tokio::select! {
                answer = self.answers_rx.recv() => match answer {
                    Some((from, body)) => self.answer(client, from, &body).await,
                    None => Ok(()),
                },
                _ = sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                    self.expire().await;
                    Ok(())
                },
                event = client.next() => match event {
                    Ok(event) => self.event(client, event, now_ms()).await,
                    Err(e) => Err(ServeError::Hub(e)),
                },
            };
            if let Err(e) = outcome {
                self.close().await;
                return e;
            }
        }
    }

    /// A caller's own owner table. Not the native one, whose `status` would show a remote caller the orphans (and
    /// their owners) of the person's own sessions; and one per caller, because a ledger file is named by the host
    /// process, which every caller's session shares.
    fn owners_dir(&self, caller: &[u8; 32]) -> std::path::PathBuf {
        self.state.dir().join("owners").join(hex(caller))
    }

    /// End every caller's session: its input closes, so `session::serve` returns and applies the owner-loss policy.
    async fn close(&mut self) {
        for (_, mut caller) in self.callers.drain() {
            let _ = caller.input.shutdown().await;
        }
    }

    /// Close the session of every caller gone past its grace, and only theirs.
    async fn expire(&mut self) {
        let now = Instant::now();
        let due: Vec<[u8; 32]> = self.gone.iter().filter(|(_, at)| **at <= now).map(|(p, _)| *p).collect();
        for principal in due {
            self.gone.remove(&principal);
            if let Some(mut caller) = self.callers.remove(&principal) {
                self.counts.gone.fetch_add(1, Ordering::Relaxed);
                eprintln!("wmlhost hub: {} gone for {:?}; its session ends", hex(&principal), self.grace);
                let _ = caller.input.shutdown().await;
            }
        }
    }

    async fn event(&mut self, client: &mut Client, event: Event, now_ms: u64) -> Result<(), ServeError> {
        match event {
            Event::Command(opened) => self.command(client, opened, now_ms).await,
            Event::Unopened { sender, error, .. } => {
                // Nothing about the sender is verified, so nothing is sealed back to it.
                eprintln!("wmlhost hub: a command that did not open, from {}: {error:?}", hex(&sender));
                Ok(())
            }
            Event::Error(e) if e.code() == Code::Throttled => Ok(()),
            Event::Error(e) => Err(ServeError::Refused(e)),
            Event::Presence(presence) => self.presence(client, presence, now_ms).await,
            Event::Published { stream, payload, .. } => self.list(&stream, &payload, now_ms),
            _ => Ok(()),
        }
    }

    async fn command(&mut self, client: &mut Client, opened: Opened, now_ms: u64) -> Result<(), ServeError> {
        let Ok(agreement_key) = <[u8; 32]>::try_from(opened.leaf.agreement_key.as_slice()) else {
            return Ok(());
        };
        let to = Recipient { principal: opened.from, agreement_key };
        self.gone.remove(&opened.from);
        let call: Option<serde_json::Map<String, Value>> = serde_json::from_slice(&opened.body).ok();
        let seq = call.as_ref().and_then(|c| c.get("seq")).filter(|v| v.is_i64() || v.is_u64()).cloned();

        // A callers file that cannot be read refuses everyone, as an empty one does.
        let callers = self.state.callers().unwrap_or_else(|e| {
            eprintln!("wmlhost hub: {e}");
            BTreeSet::new()
        });
        if let Err(refusal) = admit(&opened, &self.revocations, &callers, now_ms) {
            self.counts.refused.fetch_add(1, Ordering::Relaxed);
            eprintln!("wmlhost hub: refused {}: {}", hex(&opened.from), refusal.reason());
            let body = json!({ "seq": seq, "error":
                { "code": "Refused", "reason": refusal.reason(), "message": refusal.message() } });
            return self.seal_back(client, &to, &opened.nonce, &body).await;
        }
        let (Some(mut call), Some(seq)) = (call, seq) else {
            self.counts.malformed.fetch_add(1, Ordering::Relaxed);
            let body = json!({ "seq": null, "error":
                { "code": "BadRequest", "message": "a call is a JSON object with a numeric seq" } });
            return self.seal_back(client, &to, &opened.nonce, &body).await;
        };

        // The session sees a seq of the host's choosing, so two callers' seqs never meet in one table.
        let ours = self.next_seq;
        self.next_seq += 1;
        call.insert("seq".into(), json!(ours));
        let frame = serde_json::to_vec(&call).expect("JSON values serialize");
        self.asked.insert(ours, Asked { to, nonce: opened.nonce, seq });
        let owners_dir = self.owners_dir(&opened.from);
        let caller = match self.callers.entry(opened.from) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let roots = self.state.roots().map_err(|e| eprintln!("wmlhost hub: {e}")).ok();
                let events = opened.leaf.scopes.iter().any(|s| s == scope::VIEW);
                let transport = Transport::Hub {
                    roots,
                    callers: callers.len(),
                    revocations_since: self.revocations_since.clone(),
                    events,
                };
                match (self.make_host)(transport) {
                    Ok(mut host) => {
                        host.owners_dir = Some(owners_dir);
                        if events && !self.streams.contains_key(&opened.from) {
                            let start = now_ms.saturating_mul(1_000).max(self.floor);
                            let stream = grant(&self.publisher, &self.channel_key, &to, start, now_ms)
                                .map_err(|e| ServeError::State(std::io::Error::other(format!("{e:?}"))))?;
                            client
                                .publish(&stream.1, Kind::SessionEvents, Bytes::from(stream.2))
                                .await
                                .map_err(ServeError::Hub)?;
                            self.streams.insert(opened.from, stream.0);
                        }
                        v.insert(open_session(opened.from, host, self.answers_tx.clone()))
                    }
                    Err(e) => {
                        let asked = self.asked.remove(&ours).expect("just inserted");
                        let body = json!({ "seq": asked.seq, "error":
                            { "code": "Failed", "message": format!("cannot start a session: {e}") } });
                        return self.seal_back(client, &asked.to, &asked.nonce, &body).await;
                    }
                }
            }
        };
        if framing::write_frame_max(&mut caller.input, &frame, framing::MAX_IN).await.is_err() {
            // The session ended under it; the next call from this caller starts a new one.
            self.callers.remove(&opened.from);
            let asked = self.asked.remove(&ours).expect("just inserted");
            let body = json!({ "seq": asked.seq, "error": { "code": "Failed", "message": "the session ended" } });
            return self.seal_back(client, &asked.to, &asked.nonce, &body).await;
        }
        self.counts.routed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Something a session wrote: an answer goes back to whoever asked, sealed; an event is published on its caller's
    /// channel.
    async fn answer(&mut self, client: &mut Client, from: [u8; 32], body: &[u8]) -> Result<(), ServeError> {
        let Ok(mut msg) = serde_json::from_slice::<serde_json::Map<String, Value>>(body) else { return Ok(()) };
        let Some(ours) = msg.get("seq").and_then(Value::as_u64) else {
            msg.insert("v".into(), json!(session::PROTOCOL));
            return self.publish(client, &from, &serde_json::to_vec(&msg).expect("JSON values serialize")).await;
        };
        let Some(asked) = self.asked.remove(&ours) else { return Ok(()) };
        msg.insert("seq".into(), asked.seq);
        self.counts.answered.fetch_add(1, Ordering::Relaxed);
        self.seal_back(client, &asked.to, &asked.nonce, &Value::Object(msg)).await
    }

    /// One session event, as the session wrote it, sealed under the caller's key and published on its channel.
    async fn publish(&mut self, client: &mut Client, from: &[u8; 32], event: &[u8]) -> Result<(), ServeError> {
        let Some(counter) = self.streams.get(from).map(|s| s.counter + 1) else {
            self.counts.unpublished.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        // The mark moves ahead BEFORE a frame passes it, so a crash between frames leaves it above every counter used.
        if counter > self.leased {
            let mark = counter + COUNTER_LEASE;
            self.state.write_counter_mark(mark).map_err(ServeError::State)?;
            self.leased = mark;
        }
        let stream = self.streams.get_mut(from).expect("looked up above");
        stream.counter = counter;
        let sender = Sender { identity: &self.publisher.identity, chain: &self.publisher.chain };
        let frame = match seal_frame(&sender, &stream.channel, &stream.key, stream.counter, event) {
            Ok(frame) if frame.len() <= MAX_STREAM_FRAME_BYTES => frame,
            _ => {
                self.counts.unpublished.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };
        client.publish(&stream.channel, Kind::SessionEvents, Bytes::from(frame)).await.map_err(ServeError::Hub)?;
        self.counts.events.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn seal_back(
        &mut self,
        client: &mut Client,
        to: &Recipient,
        nonce: &[u8; NONCE_BYTES],
        body: &Value,
    ) -> Result<(), ServeError> {
        let bytes = serde_json::to_vec(body).expect("JSON values serialize");
        client.result(to, nonce, &bytes).await.map_err(ServeError::Hub)
    }

    /// A principal of the account came online: one holding `may_revoke`, verified here, is followed from now on.
    /// A caller with a session going away starts its grace; coming back ends it.
    async fn presence(&mut self, client: &mut Client, presence: Presence, now_ms: u64) -> Result<(), ServeError> {
        if let Ok(principal) = <[u8; 32]>::try_from(presence.principal.as_slice()) {
            if presence.online {
                self.gone.remove(&principal);
            } else if self.callers.contains_key(&principal) {
                self.gone.entry(principal).or_insert_with(|| Instant::now() + self.grace);
            }
        }
        if !presence.online || presence.chain.is_empty() {
            return Ok(());
        }
        let Ok(verified) = verify_chain(self.revocations.root(), &presence.chain, now_ms) else { return Ok(()) };
        if !verified.leaf.may_revoke || presence.principal != verified.principal {
            return Ok(());
        }
        if self.revocations.saw_revoker(verified.principal, now_ms) {
            self.note();
            self.revocation_files.write_revokers(&self.revocations).map_err(ServeError::State)?;
            self.follow(client, &verified.principal).await?;
        }
        Ok(())
    }

    /// A list on a revoker's channel: applied if it verifies, and written down before anything else is decided.
    fn list(&mut self, stream: &StreamRef, payload: &[u8], now_ms: u64) -> Result<(), ServeError> {
        let Ok(publisher) = <[u8; 32]>::try_from(stream.publisher.as_slice()) else { return Ok(()) };
        if !self.revocations.revokers().any(|r| *r == publisher)
            || stream.channel != self.channel_key.channel(REVOCATIONS_PURPOSE, &publisher)
        {
            return Ok(());
        }
        let Ok(list) = RevocationList::decode(payload) else { return Ok(()) };
        match self.revocations.apply(&list, now_ms) {
            Ok(_) => {
                self.note();
                self.revocation_files.write_revocation_list(&list).map_err(ServeError::State)?;
                self.revocation_files.write_revokers(&self.revocations).map_err(ServeError::State)?;
                self.counts.lists.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(RevocationError::Stale) => Ok(()),
            Err(e) => {
                eprintln!("wmlhost hub: a revocation list from {} that does not verify: {e:?}", hex(&publisher));
                Ok(())
            }
        }
    }

    async fn follow(&mut self, client: &mut Client, revoker: &[u8; 32]) -> Result<(), ServeError> {
        let channel = self.channel_key.channel(REVOCATIONS_PURPOSE, revoker);
        client.subscribe(revoker, &channel, None).await.map_err(ServeError::Hub)
    }
}

/// A caller's event stream, and its key wrapped to it for the keys channel: `(stream, keys channel, wrapped)`.
///
/// `start` is the counter before the first frame: the clock in microseconds, or the persisted mark if that is higher,
/// so a host restarted with a new key never repeats a counter a reader passed on the same channel (wmlhub-seal: a
/// counter "never repeats across key rotations"), even with its clock stepped back. The grant covers the stream from
/// its first frame.
fn grant(
    publisher: &Publisher,
    channels: &ChannelKey,
    to: &Recipient,
    start: u64,
    now_ms: u64,
) -> Result<(Stream, Vec<u8>, Vec<u8>), String> {
    let key = StreamKey::generate().map_err(|e| e.to_string())?;
    let channel = channels.channel(EVENTS_PURPOSE, &to.principal).to_vec();
    let keys = channels.channel(KEYS_PURPOSE, &to.principal).to_vec();
    let sender = Sender { identity: &publisher.identity, chain: &publisher.chain };
    let wrapped = wrap_key(&sender, to, &channel, &key, start + 1, now_ms).map_err(|e| format!("{e:?}"))?;
    Ok((Stream { key, channel, counter: start }, keys, wrapped))
}

/// Start a caller's session: `session::serve` over an in-memory pipe, its output forwarded to the hub loop, tagged with
/// whose it is.
fn open_session(from: [u8; 32], host: Host, answers: mpsc::UnboundedSender<([u8; 32], Vec<u8>)>) -> Caller {
    let (ours, theirs) = tokio::io::duplex(SESSION_PIPE_BYTES);
    let (session_in, session_out) = tokio::io::split(theirs);
    let (mut from_session, to_session) = tokio::io::split(ours);
    tokio::spawn(async move {
        let _ = session::serve(session_in, session_out, host).await;
    });
    tokio::spawn(async move {
        while let Ok(Some(body)) = framing::read_frame_max(&mut from_session, framing::MAX_OUT).await {
            if answers.send((from, body)).is_err() {
                break;
            }
        }
    });
    Caller { input: to_session }
}
