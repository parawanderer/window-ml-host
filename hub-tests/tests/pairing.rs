//! pairing.rs — the host pairing with a hub as a runtime, the way a person does it: keys on disk, a code and a
//! fingerprint on the terminal, the account's root (a phone; here the test's root key) answering, and the host logging
//! in with what it was given. An answer that would make the host something else is refused and nothing is stored.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use window_ml_host::hub::pair::{Offer, PairError};
use window_ml_host::hub::state::State;
use wmlhub::registry::{OpenLimits, Registration, Registry};
use wmlhub_client::{Client, Config};
use wmlhub_keys::pairing::{PairingCode, fingerprint_hex};
use wmlhub_keys::{CertSpec, Identity, issue, scope};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{Certificate, PairedWith, PairingAnswer, PairingOffer, Role};
use wmlhub_seal::{AgreementKey, seal_pairing_answer};

const HUB: &str = "hub.test";
const CHANNEL_KEY: [u8; 32] = [33; 32];

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

async fn start_hub(dir: &std::path::Path) -> String {
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

/// The account's root and the device it answers from. The certificate is the ROOT's (a chain of one): the
/// coordinator's ruling is that a runtime offer is answered by the root, a phone. The phone's own connection only
/// carries the offer and the answer through the hub.
struct Root {
    root: Identity,
    phone_chain: Vec<Certificate>,
}

impl Root {
    fn new() -> Self {
        let root = Identity::from_seed([1; 32]);
        let phone = Identity::from_seed([2; 32]);
        let phone_chain = vec![
            issue(
                &root,
                &CertSpec {
                    subject: phone.public(),
                    agreement_key: AgreementKey::from_seed(&[3; 32]).public(),
                    role: Role::Client,
                    scopes: vec![scope::VIEW.into()],
                    may_pair: true,
                    may_revoke: false,
                    not_before_ms: now_ms() - 3_600_000,
                    not_after_ms: now_ms() + 3_600_000,
                    label: "the phone".into(),
                },
            )
            .unwrap(),
        ];
        Self { root, phone_chain }
    }

    async fn connect(&self, url: &str) -> Client {
        Client::connect(Config {
            url: url.to_owned(),
            hub_name: HUB.into(),
            identity: Identity::from_seed([2; 32]),
            agreement: AgreementKey::from_seed(&[3; 32]),
            chain: self.phone_chain.clone(),
            account_root: self.root.public(),
            role: Role::Client,
            invite: Vec::new(),
        })
        .await
        .unwrap()
    }

    /// The root's certificate over whichever keys and role it is handed: the honest case passes the offered ones.
    fn issue_for(&self, subject: &[u8; 32], agreement_key: [u8; 32], role: Role) -> Certificate {
        issue(
            &self.root,
            &CertSpec {
                subject: *subject,
                agreement_key,
                role,
                scopes: Vec::new(),
                may_pair: false,
                may_revoke: false,
                not_before_ms: now_ms() - 1_000,
                not_after_ms: now_ms() + 1_800_000,
                label: "the desktop".into(),
            },
        )
        .unwrap()
    }
}

/// The offer the hub is holding, once it is there: the host leaves it a moment after the test asks.
async fn offer_in_slot(client: &mut Client, code: &PairingCode) -> PairingOffer {
    for _ in 0..40 {
        if let Ok(bytes) = client.pairing_offered(&code.hash()).await {
            return PairingOffer::decode(bytes.as_slice()).expect("an offer");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the offer never reached the hub");
}

/// Pair once, with `answer` choosing what the root signs from the offer it sees.
async fn pair_with(
    answer: impl FnOnce(&Root, &PairingOffer) -> PairedWith,
) -> (tempfile::TempDir, State, String, Root, Result<PairedWith, PairError>) {
    let tmp = tempfile::tempdir().unwrap();
    let url = start_hub(tmp.path()).await;
    let root = Root::new();
    let mut phone = root.connect(&url).await;
    let state = State::at(tmp.path().join("host"));
    let keys = state.generate_keys().unwrap();
    let offer = Offer::new(&keys, "the desktop", now_ms()).unwrap();
    let code = PairingCode::parse(offer.code()).expect("the printed code is a code");
    let shown = offer.fingerprint();
    let confirm = async {
        let offered = offer_in_slot(&mut phone, &code).await;
        let identity: [u8; 32] = offered.identity_key.as_slice().try_into().unwrap();
        let agreement: [u8; 32] = offered.agreement_key.as_slice().try_into().unwrap();
        assert_eq!(fingerprint_hex(&identity, &agreement), shown, "both screens show the same fingerprint");
        assert_eq!(offered.role(), Role::Runtime, "it asks to be a runtime");
        let paired = answer(&root, &offered);
        let sealed = seal_pairing_answer(&agreement, &paired).unwrap();
        phone.pairing_answer(&code.hash(), PairingAnswer { sealed }.encode_to_vec()).await.unwrap();
    };
    let mut left = offer.leave(&url).await.expect("the hub holds the offer");
    let (result, ()) = tokio::join!(left.answer(Duration::from_secs(20), now_ms), confirm);
    (tmp, state, url, root, result)
}

fn honest(root: &Root, offered: &PairingOffer, role: Role) -> PairedWith {
    let identity: [u8; 32] = offered.identity_key.as_slice().try_into().unwrap();
    let agreement: [u8; 32] = offered.agreement_key.as_slice().try_into().unwrap();
    PairedWith {
        chain: vec![root.issue_for(&identity, agreement, role)],
        account_root: root.root.public().to_vec(),
        channel_key: CHANNEL_KEY.to_vec(),
    }
}

// --- pairing as a runtime ---

#[tokio::test]
async fn the_host_pairs_with_the_root_as_a_runtime_and_logs_in_with_what_it_was_given() {
    let (_tmp, state, url, root, result) = pair_with(|r, o| honest(r, o, Role::Runtime)).await;
    let paired = result.expect("an answer for this host that verifies");
    state.write_paired(&paired).unwrap();

    // a restart: read the state back and log in with it
    let restarted = State::at(state.dir());
    let keys = restarted.keys().unwrap().expect("its keys");
    let stored = restarted.paired().unwrap().expect("what it was paired with");
    let client = Client::connect(Config {
        url: url.clone(),
        hub_name: HUB.into(),
        identity: keys.identity,
        agreement: keys.agreement,
        chain: stored.chain,
        account_root: root.root.public(),
        role: Role::Runtime,
        invite: Vec::new(),
    })
    .await
    .expect("the host logs in as a runtime with what pairing gave it");
    assert_eq!(client.account(), root.connect(&url).await.account(), "on the account that paired it");
}

// --- answers that would make the host something else ---

#[tokio::test]
async fn a_certificate_for_another_role_is_refused_and_nothing_is_stored() {
    for role in [Role::Client, Role::BoxConnector] {
        let (_tmp, state, _url, _root, result) = pair_with(move |r, o| honest(r, o, role)).await;
        assert!(matches!(result, Err(PairError::WrongRole(got)) if got == role), "{role:?}: {result:?}");
        assert!(state.paired().unwrap().is_none(), "nothing written");
    }
}

#[tokio::test]
async fn a_certificate_for_another_principal_is_refused() {
    // what a hub that substituted the keys ends up doing: a certificate for a principal it controls, sealed to the
    // agreement key the host actually offered so that it opens
    let (_tmp, state, _url, _root, result) = pair_with(|r, o| {
        let agreement: [u8; 32] = o.agreement_key.as_slice().try_into().unwrap();
        let someone_else = Identity::from_seed([99; 32]).public();
        PairedWith {
            chain: vec![r.issue_for(&someone_else, agreement, Role::Runtime)],
            account_root: r.root.public().to_vec(),
            channel_key: CHANNEL_KEY.to_vec(),
        }
    })
    .await;
    assert!(matches!(result, Err(PairError::NotMine)), "{result:?}");
    assert!(state.paired().unwrap().is_none());
}

#[tokio::test]
async fn a_certificate_over_another_agreement_key_is_refused() {
    let (_tmp, state, _url, _root, result) = pair_with(|r, o| {
        let identity: [u8; 32] = o.identity_key.as_slice().try_into().unwrap();
        PairedWith {
            chain: vec![r.issue_for(&identity, [77; 32], Role::Runtime)],
            account_root: r.root.public().to_vec(),
            channel_key: CHANNEL_KEY.to_vec(),
        }
    })
    .await;
    assert!(matches!(result, Err(PairError::NotMyAgreementKey)), "{result:?}");
    assert!(state.paired().unwrap().is_none());
}

#[tokio::test]
async fn a_chain_to_another_root_than_the_one_it_names_is_refused() {
    let (_tmp, state, _url, _root, result) = pair_with(|r, o| {
        let mut paired = honest(r, o, Role::Runtime);
        paired.account_root = Identity::from_seed([42; 32]).public().to_vec();
        paired
    })
    .await;
    assert!(matches!(result, Err(PairError::Chain(_))), "{result:?}");
    assert!(state.paired().unwrap().is_none());
}

// --- the CLI's refusals ---

#[test]
fn hub_allow_refuses_what_is_not_a_principal_and_status_says_nobody_may_call() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("host").display().to_string();
    let run = |args: &[&str]| {
        let mut all = vec!["--state-dir".to_owned(), dir.clone()];
        all.extend(args.iter().map(|s| s.to_string()));
        window_ml_host::hub::cli::main(&all)
    };
    assert_eq!(run(&["allow", "not-a-principal"]), 1);
    assert_eq!(run(&["allow", &"ab".repeat(32)]), 0);
    assert_eq!(State::at(&dir).callers().unwrap().len(), 1);
    assert_eq!(run(&["roots", "add", "/no/such/dir/anywhere"]), 1, "a root must exist");
    assert!(State::at(&dir).roots().unwrap().is_empty());
    assert_eq!(run(&["status"]), 0, "status of an unpaired host is not an error");
}
