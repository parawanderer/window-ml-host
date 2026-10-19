//! pair.rs — pairing the host with a hub: the half that runs at this machine. wmlbox's flow
//! (window-ml-hub, `crates/connector/src/pair.rs`; its `docs/design/pairing.md`, option C), as a RUNTIME.
//!
//! The host has keys and nothing else. It chooses a code, shows the code and the fingerprint of its own keys, and
//! leaves an offer under the hash of that code. A person carries the code to the account's root (a phone) or a device
//! it delegated pairing to, compares the fingerprint on both screens, and leaves a sealed answer in the same slot.
//!
//! The comparison is the whole of the security: a hub cannot mint a certificate, but it can substitute the keys in the
//! offer it holds, and then it is the hub that gets paired. So this prints the fingerprint of what it actually offered,
//! and refuses an answer that does not name its own keys or that was issued for another role.

use std::fmt;
use std::time::Duration;

use wmlhub_client::{ClientError, Pairing};
use wmlhub_keys::pairing::{PairingCode, fingerprint_hex};
use wmlhub_keys::{ChainError, MAX_LABEL_BYTES, principal_id, verify_chain};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::{PairedWith, PairingAnswer, PairingOffer, Role};
use wmlhub_seal::{OpenError, open_pairing_answer};

use super::state::Keys;

/// How long the host waits to be paired: the hub holds a slot for ten minutes, so longer is waiting for nothing.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);

/// The role the host asks to be, and the only one it accepts a certificate for: it runs calls and publishes their
/// events, as a browser runtime does (RUNTIME_HUB.md: "a desktop runtime holds a shell").
pub const ROLE: Role = Role::Runtime;

#[derive(Debug)]
pub enum PairError {
    Random(getrandom::Error),
    /// the label is longer than a certificate may carry
    Label(usize),
    /// the hub refused the offer, or the socket failed
    Hub(ClientError),
    /// nobody answered inside the window the hub holds a slot for
    TimedOut,
    /// what was left in the slot is not a `PairingAnswer`
    Malformed,
    /// it did not open with the key the offer carried: the answer was sealed for somebody else
    Sealed(OpenError),
    /// the chain does not verify to the account root that came with it
    Chain(ChainError),
    /// the certificate names another principal, so this host was not what got paired
    NotMine,
    /// the certificate names another agreement key, so nothing sealed to this host would open
    NotMyAgreementKey,
    /// the certificate was issued for another role
    WrongRole(Role),
}

/// An offer the host has made, or is about to: the code and fingerprint to show, and the wait for an answer.
pub struct Offer<'a> {
    keys: &'a Keys,
    code: PairingCode,
    offer: Vec<u8>,
}

impl<'a> Offer<'a> {
    /// Choose a code and build the offer. Nothing is sent yet, so a caller shows the code and fingerprint first.
    pub fn new(keys: &'a Keys, label: &str, now_ms: u64) -> Result<Self, PairError> {
        if label.len() > MAX_LABEL_BYTES {
            return Err(PairError::Label(label.len()));
        }
        let code = PairingCode::generate().map_err(PairError::Random)?;
        let offer = PairingOffer {
            identity_key: keys.identity.public().to_vec(),
            agreement_key: keys.agreement.public().to_vec(),
            role: ROLE as i32,
            label: label.to_owned(),
            offered_at_ms: now_ms,
        }
        .encode_to_vec();
        Ok(Self { keys, code, offer })
    }

    /// The code the person carries to a device that may pair.
    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    /// The fingerprint of the keys in this offer, which the person compares on both screens.
    pub fn fingerprint(&self) -> String {
        fingerprint_hex(&self.keys.identity.public(), &self.keys.agreement.public())
    }

    /// Leave the offer with the hub. Separate from the wait, so an unreachable hub fails before anyone carries a code.
    pub async fn leave(&self, url: &str) -> Result<Left<'_>, PairError> {
        let pairing = Pairing::offer(url, &self.code.hash(), self.offer.clone()).await.map_err(PairError::Hub)?;
        Ok(Left { offer: self, pairing })
    }
}

/// An offer the hub is now holding, waiting for an answer.
pub struct Left<'a> {
    offer: &'a Offer<'a>,
    pairing: Pairing,
}

impl Left<'_> {
    /// Wait for an answer, then check that it is for this host and verifies to the account root inside it.
    pub async fn answer(&mut self, window: Duration, now_ms: impl Fn() -> u64) -> Result<PairedWith, PairError> {
        let answer = match tokio::time::timeout(window, self.pairing.answer()).await {
            Ok(answer) => answer.map_err(PairError::Hub)?,
            Err(_) => return Err(PairError::TimedOut),
        };
        let answer = PairingAnswer::decode(answer.as_slice()).map_err(|_| PairError::Malformed)?;
        let paired = open_pairing_answer(&self.offer.keys.agreement, &answer.sealed).map_err(PairError::Sealed)?;
        check(self.offer.keys, &paired, now_ms())?;
        Ok(paired)
    }
}

/// What the host refuses to store: anything it could not then log in with, or that makes it something else.
pub fn check(keys: &Keys, paired: &PairedWith, now_ms: u64) -> Result<(), PairError> {
    let root: [u8; 32] = paired.account_root.as_slice().try_into().map_err(|_| PairError::Malformed)?;
    let verified = verify_chain(&root, &paired.chain, now_ms).map_err(PairError::Chain)?;
    if verified.principal != principal_id(&keys.identity.public()) {
        return Err(PairError::NotMine);
    }
    if verified.leaf.agreement_key != keys.agreement.public() {
        return Err(PairError::NotMyAgreementKey);
    }
    if verified.leaf.role() != ROLE {
        return Err(PairError::WrongRole(verified.leaf.role()));
    }
    Ok(())
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(e) => write!(f, "no random source: {e}"),
            Self::Label(len) => write!(f, "the label is {len} bytes; a certificate carries at most {MAX_LABEL_BYTES}"),
            Self::Hub(ClientError::Transport(e)) => write!(f, "cannot reach the hub: {e}"),
            Self::Hub(ClientError::Refused(e)) => write!(f, "the hub refused the offer: {:?} {}", e.code(), e.message),
            Self::Hub(e) => write!(f, "the hub: {e:?}"),
            Self::TimedOut => write!(f, "nobody paired it within {} minutes", PAIRING_WINDOW.as_secs() / 60),
            Self::Malformed => write!(f, "what was left in the pairing slot is not an answer"),
            Self::Sealed(e) => write!(f, "the answer was not sealed to this host's key: {e:?}"),
            Self::Chain(e) => write!(f, "the certificate does not verify to the account root it came with: {e:?}"),
            Self::NotMine => write!(f, "the certificate names another principal: this host was not what got paired"),
            Self::NotMyAgreementKey => {
                write!(f, "the certificate names another agreement key, so nothing sealed to it would open")
            }
            Self::WrongRole(role) => write!(f, "the certificate was issued for {role:?}, not {ROLE:?}"),
        }
    }
}
