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
//! What a session says unprompted (`done`) is H3's: published on the host's channel. This slice drops it.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::sync::mpsc;
use wmlhub_client::{Client, ClientError, Event};
use wmlhub_connector::revoked::{NotNow, Revocations};
use wmlhub_connector::serve::REVOCATIONS_PURPOSE;
use wmlhub_keys::revocation::RevocationError;
use wmlhub_keys::{hex, scope, verify_chain};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Error as HubError, Presence, RevocationList, StreamRef, error::Code};
use wmlhub_seal::{ChannelKey, NONCE_BYTES, Opened, Recipient};

use super::state::State;
use crate::framing;
use crate::session::{self, Host, Transport};

/// The one scope a call to this host is asked under.
pub const SCOPE: &str = scope::DESKTOP;

/// How much a caller's session may have in flight between it and the hub loop, each way.
const SESSION_PIPE_BYTES: usize = 4 << 20;

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
/// `owners_dir` is replaced by the caller's own.
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
    /// session events dropped: publishing them is H3
    pub events: AtomicU64,
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

/// The host on one hub connection.
pub struct Serving<'a> {
    state: &'a State,
    channel_key: ChannelKey,
    revocations: Revocations,
    /// wmlbox's state type, over the same directory, for the two revocation files only
    revocation_files: wmlhub_connector::State,
    make_host: Arc<MakeHost>,
    callers: HashMap<[u8; 32], Caller>,
    asked: HashMap<u64, Asked>,
    next_seq: u64,
    answers_tx: mpsc::UnboundedSender<Vec<u8>>,
    answers_rx: mpsc::UnboundedReceiver<Vec<u8>>,
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
        make_host: Arc<MakeHost>,
    ) -> std::io::Result<Self> {
        let revocation_files = wmlhub_connector::State::at(state.dir());
        let revocations = revocation_files.revocations(&account_root)?;
        let (answers_tx, answers_rx) = mpsc::unbounded_channel();
        let serving = Self {
            state,
            channel_key,
            revocations,
            revocation_files,
            make_host,
            callers: HashMap::new(),
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
            let outcome = tokio::select! {
                answer = self.answers_rx.recv() => match answer {
                    Some(body) => self.answer(client, &body).await,
                    None => Ok(()),
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
                let transport =
                    Transport::Hub { roots, callers: callers.len(), revocations_since: self.revocations_since.clone() };
                match (self.make_host)(transport) {
                    Ok(mut host) => {
                        host.owners_dir = Some(owners_dir);
                        v.insert(open_session(host, self.answers_tx.clone()))
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

    /// Something a session wrote: an answer goes back to whoever asked, sealed; an event is H3's.
    async fn answer(&mut self, client: &mut Client, body: &[u8]) -> Result<(), ServeError> {
        let Ok(mut msg) = serde_json::from_slice::<serde_json::Map<String, Value>>(body) else { return Ok(()) };
        let Some(ours) = msg.get("seq").and_then(Value::as_u64) else {
            self.counts.events.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        let Some(asked) = self.asked.remove(&ours) else { return Ok(()) };
        msg.insert("seq".into(), asked.seq);
        self.counts.answered.fetch_add(1, Ordering::Relaxed);
        self.seal_back(client, &asked.to, &asked.nonce, &Value::Object(msg)).await
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
    async fn presence(&mut self, client: &mut Client, presence: Presence, now_ms: u64) -> Result<(), ServeError> {
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

/// Start a caller's session: `session::serve` over an in-memory pipe, its output forwarded to the hub loop.
fn open_session(host: Host, answers: mpsc::UnboundedSender<Vec<u8>>) -> Caller {
    let (ours, theirs) = tokio::io::duplex(SESSION_PIPE_BYTES);
    let (session_in, session_out) = tokio::io::split(theirs);
    let (mut from_session, to_session) = tokio::io::split(ours);
    tokio::spawn(async move {
        let _ = session::serve(session_in, session_out, host).await;
    });
    tokio::spawn(async move {
        while let Ok(Some(body)) = framing::read_frame_max(&mut from_session, framing::MAX_OUT).await {
            if answers.send(body).is_err() {
                break;
            }
        }
    });
    Caller { input: to_session }
}
