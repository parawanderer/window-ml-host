//! serve.rs — the host answering calls over an in-process hub, as a desktop runtime. A caller holding `desktop`, not
//! revoked, and listed in `hub-callers` runs a program in a root the person granted; every other caller is refused
//! with the refusal sealed back, and nothing is spawned. A `configure` may narrow the person's roots, never widen them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::TcpListener;
use window_ml_host::env::NoSecrets;
use window_ml_host::hub::serve::{Counts, MakeHost, Serving};
use window_ml_host::hub::state::State;
use window_ml_host::sandbox;
use window_ml_host::session::Host;
use window_ml_host::store::Store;
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_client::{Client, Config, Event};
use wmlhub_keys::{CertSpec, Identity, account_id, issue, principal_id, scope};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, Kind, PairedWith, Role};
use wmlhub_seal::{AgreementKey, ChannelKey, Recipient, Sender, seal_command};

const HUB: &str = "hub.test";
const CHANNEL_KEY: [u8; 32] = [33; 32];

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

async fn start_hub(dir: &Path) -> String {
    let registry = Registry::open(dir.join("hub"), Registration::Open, OpenLimits::default()).unwrap();
    let config = wmlhub::Config {
        auth: wmlhub::Auth::Keys { hub_name: HUB.into(), registry: Arc::new(registry) },
        ..wmlhub::Config::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(wmlhub::serve(listener, config, 1));
    format!("ws://{addr}")
}

/// A principal of the test account: its keys and the root's certificate over them.
struct Device {
    identity_seed: [u8; 32],
    agreement_seed: [u8; 32],
    chain: Vec<Certificate>,
    role: Role,
}

impl Device {
    fn new(root: &Identity, seed: u8, role: Role, scopes: &[&str], may_revoke: bool) -> Self {
        let identity_seed = [seed; 32];
        let agreement_seed = [seed.wrapping_add(100); 32];
        let chain = vec![
            issue(
                root,
                &CertSpec {
                    subject: Identity::from_seed(identity_seed).public(),
                    agreement_key: AgreementKey::from_seed(&agreement_seed).public(),
                    role,
                    scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                    may_pair: false,
                    may_revoke,
                    not_before_ms: now_ms() - 3_600_000,
                    not_after_ms: now_ms() + 3_600_000,
                    label: String::new(),
                },
            )
            .unwrap(),
        ];
        Self { identity_seed, agreement_seed, chain, role }
    }

    fn id(&self) -> [u8; 32] {
        principal_id(&Identity::from_seed(self.identity_seed).public())
    }

    async fn connect(&self, url: &str, root: &Identity) -> Client {
        Client::connect(Config {
            url: url.to_owned(),
            hub_name: HUB.into(),
            identity: Identity::from_seed(self.identity_seed),
            agreement: AgreementKey::from_seed(&self.agreement_seed),
            chain: self.chain.clone(),
            account_root: root.public(),
            role: self.role,
            invite: Vec::new(),
        })
        .await
        .unwrap()
    }
}

/// The desktop: its hub state (paired by the root, as `wmlhost hub pair` would leave it), the one root the person
/// granted, and a client logged in as it.
struct Desktop {
    _tmp: tempfile::TempDir,
    url: String,
    root: Identity,
    state: State,
    workspace: PathBuf,
    chain: Vec<Certificate>,
}

impl Desktop {
    async fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let url = start_hub(tmp.path()).await;
        let root = Identity::from_seed([1; 32]);
        let state = State::at(tmp.path().join("host"));
        let keys = state.generate_keys().unwrap();
        let chain = vec![
            issue(
                &root,
                &CertSpec {
                    subject: keys.identity.public(),
                    agreement_key: keys.agreement.public(),
                    role: Role::Runtime,
                    scopes: Vec::new(),
                    may_pair: false,
                    may_revoke: false,
                    not_before_ms: now_ms() - 1_000,
                    not_after_ms: now_ms() + 3_600_000,
                    label: "the desktop".into(),
                },
            )
            .unwrap(),
        ];
        state
            .write_paired(&PairedWith {
                chain: chain.clone(),
                account_root: root.public().to_vec(),
                channel_key: CHANNEL_KEY.to_vec(),
            })
            .unwrap();
        let workspace = tmp.path().join("granted");
        std::fs::create_dir_all(workspace.join("sub")).unwrap();
        let workspace = state.add_root(&workspace).unwrap();
        Self { _tmp: tmp, url, root, state, workspace, chain }
    }

    fn recipient(&self) -> Recipient {
        let keys = self.state.keys().unwrap().unwrap();
        Recipient { principal: principal_id(&keys.identity.public()), agreement_key: keys.agreement.public() }
    }

    async fn client(&self) -> Client {
        let keys = self.state.keys().unwrap().unwrap();
        Client::connect(Config {
            url: self.url.clone(),
            hub_name: HUB.into(),
            identity: keys.identity,
            agreement: keys.agreement,
            chain: self.chain.clone(),
            account_root: self.root.public(),
            role: Role::Runtime,
            invite: Vec::new(),
        })
        .await
        .unwrap()
    }

    fn serving(&self, store: &Path) -> Serving<'_> {
        let store = Arc::new(Store::create(store).unwrap());
        let make_host: Arc<MakeHost> = Arc::new(move |transport| {
            Ok(Host {
                sandbox: sandbox::probe(),
                secrets: Box::new(NoSecrets),
                store: store.clone(),
                host_env: Box::new(|k| std::env::var(k).ok()),
                owners_dir: None,
                warden: None,
                transport,
            })
        });
        Serving::new(&self.state, self.root.public(), ChannelKey::from_bytes(CHANNEL_KEY), make_host).unwrap()
    }

    /// A caller holding `scopes`, not yet allowed.
    fn caller(&self, seed: u8, scopes: &[&str]) -> Device {
        Device::new(&self.root, seed, Role::Client, scopes, false)
    }
}

/// One call, asked under `scope`, and its sealed answer.
async fn call(client: &mut Client, to: &Recipient, scope: &str, seq: u64, name: &str, args: Value) -> Value {
    let body = serde_json::to_vec(&json!({ "seq": seq, "call": name, "args": args })).unwrap();
    let nonce = client.command(to, scope, &body).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Event::Result(r) = client.next().await.unwrap() {
                if r.answers == Some(nonce) {
                    return serde_json::from_slice::<Value>(&r.body).unwrap();
                }
            }
        }
    });
    answer.await.expect("an answer, not silence")
}

/// configure, spawn `touch marker` in the granted root, start it: the whole of running a program.
async fn touch(client: &mut Client, to: &Recipient, scope: &str, workspace: &Path) -> Vec<Value> {
    let cwd = workspace.join("sub");
    let c = call(client, to, scope, 10, "configure", json!({ "roots": [cwd] })).await;
    let s = call(client, to, scope, 11, "spawn", json!({ "argv": ["touch", "marker"], "cwd": cwd })).await;
    let id = s["value"]["id"].clone();
    let st = call(client, to, scope, 12, "start", json!({ "id": id })).await;
    vec![c, s, st]
}

fn refused(answers: &[Value], reason: &str) {
    for a in answers {
        assert_eq!(a["error"]["code"], "Refused", "{a}");
        assert_eq!(a["error"]["reason"], reason, "{a}");
        assert!(a.get("value").is_none(), "{a}");
    }
}

/// Nothing ran: no marker after a moment, and the host routed nothing to a session.
async fn nothing_spawned(workspace: &Path, counts: &Counts, routed_before: u64) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!workspace.join("sub/marker").exists(), "the program never ran");
    assert_eq!(counts.routed.load(Ordering::Relaxed), routed_before, "no call reached a session");
}

async fn eventually_exists(p: &Path) {
    for _ in 0..100 {
        if p.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} never appeared", p.display());
}

// --- a caller the person allowed ---

#[tokio::test]
async fn an_allowed_desktop_caller_runs_a_program_in_a_granted_root_and_hello_says_what_bounds_it() {
    let desk = Desktop::new().await;
    let caller = desk.caller(20, &[scope::DESKTOP]);
    desk.state.allow(&caller.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        let h = call(&mut client, &to, scope::DESKTOP, 7, "hello", json!({})).await;
        assert_eq!(h["seq"], 7, "the caller's own seq comes back");
        assert_eq!(h["value"]["transport"], "hub");
        assert_eq!(h["value"]["hub"]["roots"], json!([desk.workspace]));
        assert_eq!(h["value"]["hub"]["callers"], 1);
        assert_eq!(h["value"]["sandbox"]["available"], sandbox::probe().available, "the host's own fact: {h}");
        assert_eq!(h["value"]["hub"]["revocationsAgeMs"], Value::Null, "no revoker seen, nothing to go stale: {h}");
        if !h["value"]["sandbox"]["available"].as_bool().unwrap() {
            assert!(std::env::var_os("WMLHOST_REQUIRE_SANDBOX").is_none(), "CI has a sandbox: {h}");
            eprintln!("no sandbox on this machine: skipping the run");
            return;
        }
        let answers = touch(&mut client, &to, scope::DESKTOP, &desk.workspace).await;
        assert_eq!(answers[0]["seq"], 10);
        assert_eq!(answers[0]["value"]["sandboxed"], true, "{}", answers[0]);
        assert!(answers[1]["value"]["id"].is_string(), "{}", answers[1]);
        assert!(answers[2]["value"]["pid"].is_u64(), "{}", answers[2]);
        eventually_exists(&desk.workspace.join("sub/marker")).await;
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn a_configure_may_narrow_the_granted_roots_and_never_widen_them_or_turn_the_sandbox_off() {
    let desk = Desktop::new().await;
    let caller = desk.caller(21, &[scope::DESKTOP]);
    desk.state.allow(&caller.id()).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        let outside = elsewhere.path().canonicalize().unwrap();
        let wide = call(&mut client, &to, scope::DESKTOP, 1, "configure", json!({ "roots": [outside] })).await;
        assert_eq!(wide["error"]["code"], "BadRequest", "{wide}");
        assert!(wide["error"]["message"].as_str().unwrap().contains(outside.to_str().unwrap()), "names the root");
        let parent = desk.workspace.parent().unwrap();
        let above = call(&mut client, &to, scope::DESKTOP, 2, "configure", json!({ "roots": [parent] })).await;
        assert_eq!(above["error"]["code"], "BadRequest", "the parent of a granted root is wider: {above}");
        let some_wide =
            call(&mut client, &to, scope::DESKTOP, 3, "configure", json!({ "roots": [desk.workspace, parent] })).await;
        assert_eq!(some_wide["error"]["code"], "BadRequest", "one wide root refuses the whole: {some_wide}");
        let plain = json!({ "roots": [desk.workspace], "sandbox": false });
        let plain = call(&mut client, &to, scope::DESKTOP, 4, "configure", plain).await;
        assert_eq!(plain["error"]["code"], "BadRequest", "plain host mode is not the caller's to choose: {plain}");
        let spawn = json!({ "argv": ["touch", "marker"], "cwd": desk.workspace.join("sub") });
        let s = call(&mut client, &to, scope::DESKTOP, 5, "spawn", spawn).await;
        assert_eq!(s["error"]["code"], "NotConfigured", "no refused configure took effect: {s}");
        let sandboxed = sandbox::probe().available;
        let narrow = json!({ "roots": [desk.workspace.join("sub")] });
        let narrow = call(&mut client, &to, scope::DESKTOP, 6, "configure", narrow).await;
        if sandboxed {
            assert!(narrow["value"].is_object(), "a root within a granted one: {narrow}");
        } else {
            assert_eq!(narrow["error"]["code"], "SandboxFailed", "no sandbox, nothing over the hub: {narrow}");
        }
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn with_no_granted_roots_every_configure_is_not_configured() {
    let desk = Desktop::new().await;
    std::fs::remove_file(desk.state.dir().join(window_ml_host::hub::state::ROOTS_FILE)).unwrap();
    let caller = desk.caller(22, &[scope::DESKTOP]);
    desk.state.allow(&caller.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        let h = call(&mut client, &to, scope::DESKTOP, 1, "hello", json!({})).await;
        assert_eq!(h["value"]["hub"]["roots"], json!([]));
        let c = call(&mut client, &to, scope::DESKTOP, 2, "configure", json!({ "roots": [desk.workspace] })).await;
        assert_eq!(c["error"]["code"], "NotConfigured", "{c}");
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn each_caller_has_a_session_and_an_owner_table_of_its_own() {
    let desk = Desktop::new().await;
    let (a, b) = (desk.caller(31, &[scope::DESKTOP]), desk.caller(32, &[scope::DESKTOP]));
    desk.state.allow(&a.id()).unwrap();
    desk.state.allow(&b.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let (mut a_client, mut b_client) = (a.connect(&desk.url, &desk.root).await, b.connect(&desk.url, &desk.root).await);
    let to = desk.recipient();
    let script = async {
        let h = call(&mut a_client, &to, scope::DESKTOP, 1, "hello", json!({})).await;
        assert_eq!(h["value"]["owners"]["ledger"], true, "{h}");
        if !h["value"]["sandbox"]["available"].as_bool().unwrap() {
            assert!(std::env::var_os("WMLHOST_REQUIRE_SANDBOX").is_none(), "CI has a sandbox: {h}");
            return;
        }
        let cwd = desk.workspace.join("sub");
        call(&mut b_client, &to, scope::DESKTOP, 1, "configure", json!({ "roots": [cwd] })).await;
        let spawn = json!({ "argv": ["sleep", "5"], "cwd": cwd, "owner": { "run": "b's" } });
        let s = call(&mut b_client, &to, scope::DESKTOP, 2, "spawn", spawn).await;
        let started = call(&mut b_client, &to, scope::DESKTOP, 3, "start", json!({ "id": s["value"]["id"] })).await;
        assert!(started["value"]["pid"].is_u64(), "{started}");
        let b_status = call(&mut b_client, &to, scope::DESKTOP, 4, "status", json!({})).await;
        assert_eq!(b_status["value"]["running"].as_array().unwrap().len(), 1, "{b_status}");
        let a_status = call(&mut a_client, &to, scope::DESKTOP, 2, "status", json!({})).await;
        assert_eq!(a_status["value"]["running"], json!([]), "a sees nothing of b's: {a_status}");
        assert_eq!(a_status["value"]["orphans"], json!([]), "{a_status}");
        let a_id = call(&mut a_client, &to, scope::DESKTOP, 3, "cancel", json!({ "id": s["value"]["id"] })).await;
        assert_eq!(a_id["error"]["code"], "UnknownId", "nor can it cancel it: {a_id}");
        let mine = call(&mut b_client, &to, scope::DESKTOP, 5, "cancel", json!({ "id": s["value"]["id"] })).await;
        assert!(mine.get("error").is_none(), "b cancels its own: {mine}");
        for c in [&a, &b] {
            let dir = desk.state.dir().join("owners").join(wmlhub_keys::hex(&c.id()));
            assert!(dir.is_dir(), "{} has its own owner table", dir.display());
        }
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

// --- callers refused before anything is routed ---

#[tokio::test]
async fn a_call_asked_under_another_scope_than_desktop_is_refused_and_spawns_nothing() {
    let desk = Desktop::new().await;
    // allowed, and holding desktop: only the scope the command is asked under is wrong
    let caller = desk.caller(23, &[scope::DESKTOP, scope::VIEW]);
    desk.state.allow(&caller.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        refused(&touch(&mut client, &to, scope::VIEW, &desk.workspace).await, "scope");
        nothing_spawned(&desk.workspace, &counts, 0).await;
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn a_desktop_holder_the_person_did_not_allow_is_refused_and_a_disallow_holds_at_once() {
    let desk = Desktop::new().await;
    let stranger = desk.caller(24, &[scope::DESKTOP]);
    let friend = desk.caller(25, &[scope::DESKTOP]);
    desk.state.allow(&friend.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut s_client = stranger.connect(&desk.url, &desk.root).await;
    let mut f_client = friend.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        refused(&touch(&mut s_client, &to, scope::DESKTOP, &desk.workspace).await, "notACaller");
        nothing_spawned(&desk.workspace, &counts, 0).await;

        let h = call(&mut f_client, &to, scope::DESKTOP, 1, "hello", json!({})).await;
        assert_eq!(h["value"]["transport"], "hub", "the friend is let in: {h}");
        let routed = counts.routed.load(Ordering::Relaxed);
        desk.state.disallow(&friend.id()).unwrap();
        refused(&touch(&mut f_client, &to, scope::DESKTOP, &desk.workspace).await, "notACaller");
        nothing_spawned(&desk.workspace, &counts, routed).await;
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn an_empty_callers_file_refuses_everyone() {
    let desk = Desktop::new().await;
    let caller = desk.caller(26, &[scope::DESKTOP, scope::VIEW]);
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        let h = call(&mut client, &to, scope::DESKTOP, 1, "hello", json!({})).await;
        assert_eq!(h["error"]["reason"], "notACaller", "even hello: {h}");
        // the checks run in their order: the scope is told before the callers file is
        let v = call(&mut client, &to, scope::VIEW, 2, "hello", json!({})).await;
        assert_eq!(v["error"]["reason"], "scope", "{v}");
        nothing_spawned(&desk.workspace, &counts, 0).await;
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn a_caller_the_account_revokes_is_refused_from_the_next_call_and_spawns_nothing() {
    let desk = Desktop::new().await;
    let caller = desk.caller(27, &[scope::DESKTOP]);
    desk.state.allow(&caller.id()).unwrap();
    let revoker = Device::new(&desk.root, 28, Role::Runtime, &[], true);
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        let h = call(&mut client, &to, scope::DESKTOP, 1, "hello", json!({})).await;
        assert_eq!(h["value"]["transport"], "hub", "allowed before the list: {h}");
        // the revoker comes online after the host, so the host learns of it from presence and follows its list
        publish_list(&desk, &revoker, &[caller.id()], &counts).await;
        let routed = counts.routed.load(Ordering::Relaxed);
        refused(&touch(&mut client, &to, scope::DESKTOP, &desk.workspace).await, "revoked");
        nothing_spawned(&desk.workspace, &counts, routed).await;
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
    // written down, in wmlbox's two files, so a restart refuses the caller without hearing the list again
    for kept in ["revocations", "revokers"] {
        assert!(desk.state.dir().join(kept).exists(), "{kept} is on disk");
    }
}

/// The revoker comes online after the host (so the host learns of it from presence and follows its channel), and
/// publishes a list naming `revoked`; returns once the host has applied it.
async fn publish_list(desk: &Desktop, revoker: &Device, revoked: &[[u8; 32]], counts: &Counts) -> Client {
    let mut r_client = revoker.connect(&desk.url, &desk.root).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let list = wmlhub_keys::revocation::sign_revocations(
        &Identity::from_seed(revoker.identity_seed),
        &revoker.chain,
        account_id(&desk.root.public()),
        now_ms(),
        revoked,
        &[],
    );
    let channel = ChannelKey::from_bytes(CHANNEL_KEY).channel("revocations", &revoker.id());
    r_client.publish(&channel, Kind::SessionEvents, list.encode_to_vec().into()).await.unwrap();
    for _ in 0..50 {
        if counts.lists.load(Ordering::Relaxed) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(counts.lists.load(Ordering::Relaxed), 1, "the host applied the list");
    r_client
}

#[tokio::test]
async fn a_stale_revocation_list_refuses_an_allowed_caller_too_and_hello_says_how_old_it_is() {
    let desk = Desktop::new().await;
    let caller = desk.caller(33, &[scope::DESKTOP]);
    desk.state.allow(&caller.id()).unwrap();
    let revoker = Device::new(&desk.root, 34, Role::Runtime, &[], true);
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    // The host's clock, which the test moves on eight days without waiting them. The hub and the callers keep real
    // time, so only the host's own decisions see the jump.
    let skew = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let host_now = {
        let skew = skew.clone();
        move || now_ms() + skew.load(Ordering::Relaxed)
    };
    let script = async {
        let _r = publish_list(&desk, &revoker, &[], &counts).await;
        let h = call(&mut client, &to, scope::DESKTOP, 1, "hello", json!({})).await;
        let age = h["value"]["hub"]["revocationsAgeMs"].as_u64().expect("an age once a list is held");
        assert!(age < 60_000, "a fresh list: {h}");

        skew.store(8 * 24 * 3_600_000, Ordering::Relaxed);
        let routed = counts.routed.load(Ordering::Relaxed);
        let answers = touch(&mut client, &to, scope::DESKTOP, &desk.workspace).await;
        refused(&answers, "stale");
        nothing_spawned(&desk.workspace, &counts, routed).await;
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &host_now) => panic!("serving stopped: {e:?}"),
    }
}

#[tokio::test]
async fn a_command_from_a_certificate_without_desktop_does_not_open_and_gets_no_answer() {
    // `Client::command` refuses this before sealing; a caller that seals it anyway is refused by the seal itself
    // (the scope is not held), and the host learns nothing verified about the sender, so it answers nothing.
    let desk = Desktop::new().await;
    let caller = desk.caller(30, &[scope::VIEW]);
    desk.state.allow(&caller.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        let identity = Identity::from_seed(caller.identity_seed);
        let sender = Sender { identity: &identity, chain: &caller.chain };
        let body = serde_json::to_vec(&json!({ "seq": 1, "call": "hello", "args": {} })).unwrap();
        let (sealed, _) = seal_command(&sender, &to, scope::DESKTOP, &body, now_ms()).unwrap();
        client.direct(to.principal, Kind::Command, sealed).await.unwrap();
        let answered = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                if let Event::Result(_) = client.next().await.unwrap() {
                    return;
                }
            }
        });
        assert!(answered.await.is_err(), "no answer");
        nothing_spawned(&desk.workspace, &counts, 0).await;
        assert_eq!(counts.refused.load(Ordering::Relaxed), 0, "it never reached the host's own checks");
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}

// --- a body that is not a call ---

#[tokio::test]
async fn a_body_that_is_not_a_call_is_bad_request_and_reaches_no_session() {
    let desk = Desktop::new().await;
    let caller = desk.caller(29, &[scope::DESKTOP]);
    desk.state.allow(&caller.id()).unwrap();
    let mut host = desk.client().await;
    let store = tempfile::tempdir().unwrap();
    let mut serving = desk.serving(store.path());
    let counts = serving.counts();
    let mut client = caller.connect(&desk.url, &desk.root).await;
    let to = desk.recipient();
    let script = async {
        for body in [&b"not json"[..], br#"{"call":"hello"}"#, br#"{"seq":"7","call":"hello"}"#] {
            let nonce = client.command(&to, scope::DESKTOP, body).await.unwrap();
            let answer = loop {
                if let Event::Result(r) = client.next().await.unwrap() {
                    if r.answers == Some(nonce) {
                        break serde_json::from_slice::<Value>(&r.body).unwrap();
                    }
                }
            };
            assert_eq!(answer["error"]["code"], "BadRequest", "{answer}");
            assert_eq!(answer["seq"], Value::Null);
        }
        assert_eq!(counts.routed.load(Ordering::Relaxed), 0);
        assert_eq!(counts.malformed.load(Ordering::Relaxed), 3);
    };
    tokio::select! {
        _ = script => {}
        e = serving.run(&mut host, &now_ms) => panic!("serving stopped: {e:?}"),
    }
}
