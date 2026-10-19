//! state.rs — what the host keeps for the hub transport between runs: its two keys, what a pairing gave it, and the
//! two files only the person at this machine writes: the roots a remote caller may work in, and who may call at all.
//!
//! The keys and the pairing follow wmlbox's `State` (window-ml-hub, `crates/connector/src/state.rs`): generated once,
//! replaced only by pairing again. The two local files are the host's own (window-ml's rulings of 2026-10-19 on the
//! hub transport): a remote principal may NARROW the roots the person granted here and never widen them, and holding
//! the `desktop` scope is not enough to drive this machine, because a `may_pair` delegate anywhere in the account can
//! mint a `desktop` holder; the callers file is the one statement the account's key material cannot produce.
//!
//! Every file is written `0600` in a `0700` directory and refused if anyone else can read it.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use wmlhub_keys::{Identity, hex};
use wmlhub_proto::prost::Message;
use wmlhub_proto::v1::PairedWith;
use wmlhub_seal::AgreementKey;

/// The Ed25519 seed this host signs with, hex.
const IDENTITY_FILE: &str = "identity.key";
/// The X25519 seed sealed things are opened with, hex.
const AGREEMENT_FILE: &str = "agreement.key";
/// The `PairedWith` a pairing handed over, as it arrived: the certificate chain, the account root, the channel key.
const PAIRED_FILE: &str = "paired";
/// The directories a caller over the hub may work in, one absolute path a line, written at this machine.
pub const ROOTS_FILE: &str = "hub-roots";
/// The principals that may call this host over the hub, one hex principal id a line, written at this machine.
pub const CALLERS_FILE: &str = "hub-callers";

/// The host's hub state directory.
pub struct State {
    dir: PathBuf,
}

/// Both of the host's keys, loaded.
pub struct Keys {
    pub identity: Identity,
    pub agreement: AgreementKey,
}

/// Prints what is public about them and nothing else.
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys(identity {}, agreement {})", hex(&self.identity.public()), hex(&self.agreement.public()))
    }
}

impl State {
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// `$WMLHOST_HUB_DIR`, else `~/.config/wmlhost/hub`.
    pub fn from_system() -> io::Result<Self> {
        if let Some(dir) = std::env::var_os("WMLHOST_HUB_DIR") {
            return Ok(Self::at(dir));
        }
        let home = std::env::var_os("HOME")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no HOME, and WMLHOST_HUB_DIR is not set"))?;
        Ok(Self::at(Path::new(&home).join(".config/wmlhost/hub")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The keys, or `None` when this host has never been paired anywhere.
    pub fn keys(&self) -> io::Result<Option<Keys>> {
        let (Some(identity), Some(agreement)) = (self.seed(IDENTITY_FILE)?, self.seed(AGREEMENT_FILE)?) else {
            return Ok(None);
        };
        Ok(Some(Keys { identity: Identity::from_seed(identity), agreement: AgreementKey::from_seed(&agreement) }))
    }

    /// Generate the keys. Refuses rather than overwrite: a replaced key is a host that silently became a different
    /// principal.
    pub fn generate_keys(&self) -> io::Result<Keys> {
        let (mut identity, mut agreement) = ([0u8; 32], [0u8; 32]);
        getrandom::fill(&mut identity).map_err(io::Error::other)?;
        getrandom::fill(&mut agreement).map_err(io::Error::other)?;
        self.make_dir()?;
        self.write_secret(IDENTITY_FILE, format!("{}\n", hex(&identity)).as_bytes(), false)?;
        self.write_secret(AGREEMENT_FILE, format!("{}\n", hex(&agreement)).as_bytes(), false)?;
        Ok(Keys { identity: Identity::from_seed(identity), agreement: AgreementKey::from_seed(&agreement) })
    }

    /// What a pairing gave this host, or `None` when it has not been paired.
    pub fn paired(&self) -> io::Result<Option<PairedWith>> {
        let Some(bytes) = self.read(PAIRED_FILE)? else { return Ok(None) };
        PairedWith::decode(bytes.as_slice()).map(Some).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("{PAIRED_FILE} is not what a pairing wrote: {e}"))
        })
    }

    /// Keep what a pairing gave this host, replacing anything it was paired with before.
    pub fn write_paired(&self, paired: &PairedWith) -> io::Result<()> {
        self.make_dir()?;
        self.replace_atomically(PAIRED_FILE, &paired.encode_to_vec())
    }

    /// The roots a caller over the hub may work in, each resolved (symlinks followed) and a directory. An absent
    /// file is no roots, so every call is `NotConfigured`. A line that is not an absolute path to a directory is an
    /// error naming it, never skipped: a root silently dropped is a call refused for no reason anyone can see, and a
    /// root silently kept relative would resolve against wherever the host happened to start.
    pub fn roots(&self) -> io::Result<Vec<PathBuf>> {
        let Some(text) = self.text(ROOTS_FILE)? else { return Ok(Vec::new()) };
        let mut roots = Vec::new();
        for (n, line) in lines(&text) {
            let bad = |why: &str| self.bad_line(ROOTS_FILE, n, line, why);
            let path = Path::new(line);
            if !path.is_absolute() {
                return Err(bad("is not an absolute path"));
            }
            let real = fs::canonicalize(path).map_err(|e| bad(&format!("does not resolve ({e})")))?;
            if !real.is_dir() {
                return Err(bad("is not a directory"));
            }
            if !roots.contains(&real) {
                roots.push(real);
            }
        }
        Ok(roots)
    }

    /// Add a root, resolved now, so the file says what the host will use.
    pub fn add_root(&self, path: &Path) -> io::Result<PathBuf> {
        let real = fs::canonicalize(path)?;
        if !real.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a directory", real.display())));
        }
        let mut roots = self.roots()?;
        if !roots.contains(&real) {
            roots.push(real.clone());
        }
        let text: String = roots.iter().map(|r| format!("{}\n", r.display())).collect();
        self.make_dir()?;
        self.replace_atomically(ROOTS_FILE, text.as_bytes())?;
        Ok(real)
    }

    /// The principals that may call this host over the hub. Absent is empty, and empty refuses everyone.
    pub fn callers(&self) -> io::Result<BTreeSet<[u8; 32]>> {
        let Some(text) = self.text(CALLERS_FILE)? else { return Ok(BTreeSet::new()) };
        let mut callers = BTreeSet::new();
        for (n, line) in lines(&text) {
            let id =
                unhex(line).ok_or_else(|| self.bad_line(CALLERS_FILE, n, line, "is not a principal id (64 hex)"))?;
            callers.insert(id);
        }
        Ok(callers)
    }

    /// Allow a principal to call this host. Returns whether it was new.
    pub fn allow(&self, principal: &[u8; 32]) -> io::Result<bool> {
        let mut callers = self.callers()?;
        let new = callers.insert(*principal);
        self.write_callers(&callers)?;
        Ok(new)
    }

    /// Stop allowing a principal. Returns whether it had been allowed.
    pub fn disallow(&self, principal: &[u8; 32]) -> io::Result<bool> {
        let mut callers = self.callers()?;
        let was = callers.remove(principal);
        self.write_callers(&callers)?;
        Ok(was)
    }

    fn write_callers(&self, callers: &BTreeSet<[u8; 32]>) -> io::Result<()> {
        let text: String = callers.iter().map(|id| format!("{}\n", hex(id))).collect();
        self.make_dir()?;
        self.replace_atomically(CALLERS_FILE, text.as_bytes())
    }

    fn bad_line(&self, name: &str, n: usize, line: &str, why: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} line {n}: {line:?} {why}", self.dir.join(name).display()),
        )
    }

    fn text(&self, name: &str) -> io::Result<Option<String>> {
        let Some(bytes) = self.read(name)? else { return Ok(None) };
        String::from_utf8(bytes).map(Some).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("{} is not UTF-8", self.dir.join(name).display()))
        })
    }

    fn replace_atomically(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let aside = format!("{name}.new");
        self.write_secret(&aside, bytes, true)?;
        fs::rename(self.dir.join(&aside), self.dir.join(name))
    }

    fn seed(&self, name: &str) -> io::Result<Option<[u8; 32]>> {
        let Some(text) = self.text(name)? else { return Ok(None) };
        unhex(text.trim()).map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not 32 bytes of hex; delete it to pair again", self.dir.join(name).display()),
            )
        })
    }

    /// The file's bytes, `None` when it does not exist, and an error when anyone but its owner can read it.
    fn read(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        match fs::metadata(&self.dir) {
            Ok(meta) => check_private(&self.dir, &meta)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
        let path = self.dir.join(name);
        match fs::metadata(&path) {
            Ok(meta) => {
                check_private(&path, &meta)?;
                fs::read(&path).map(Some)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_secret(&self, name: &str, bytes: &[u8], replace: bool) -> io::Result<()> {
        let path = self.dir.join(name);
        let mut options = fs::OpenOptions::new();
        options.write(true).truncate(replace);
        if replace {
            options.create(true);
        } else {
            options.create_new(true);
        }
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&path).map_err(|e| {
            if !replace && e.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(e.kind(), format!("{} already exists: this host already has keys", path.display()))
            } else {
                e
            }
        })?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn make_dir(&self) -> io::Result<()> {
        let mut options = fs::DirBuilder::new();
        options.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut options, 0o700);
        options.create(&self.dir)?;
        // `create` leaves an existing directory's mode as it was: one others can list is refused, as a file is
        check_private(&self.dir, &fs::metadata(&self.dir)?)
    }
}

/// The non-blank, non-comment lines, trimmed, with their 1-based line numbers.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().map(|(i, l)| (i + 1, l.trim())).filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Refuse a file anyone but its owner can read, as ssh does a private key. For the roots and callers files the
/// reason is the other way round: a file others can WRITE is a file others can widen, and 0600 rules out both.
#[cfg(unix)]
fn check_private(path: &Path, meta: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is readable or writable by others (mode {mode:o}): chmod {} it",
                path.display(),
                if meta.is_dir() { 700 } else { 600 }
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path, _meta: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

/// 32 bytes from 64 hex characters, and nothing else.
pub fn unhex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (tempfile::TempDir, State) {
        let tmp = tempfile::tempdir().unwrap();
        let state = State::at(tmp.path().join("hub"));
        (tmp, state)
    }

    // --- keys and pairing ---

    #[test]
    fn keys_survive_a_restart_and_are_never_regenerated() {
        let (_tmp, state) = state();
        assert!(state.keys().unwrap().is_none());
        let made = state.generate_keys().unwrap();
        let loaded = state.keys().unwrap().expect("there");
        assert_eq!(made.identity.public(), loaded.identity.public());
        assert_eq!(made.agreement.public(), loaded.agreement.public());
        let again = state.generate_keys().unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn what_a_pairing_gave_it_round_trips_and_is_replaced_by_pairing_again() {
        let (_tmp, state) = state();
        assert!(state.paired().unwrap().is_none());
        let a = PairedWith { chain: Vec::new(), account_root: vec![3; 32], channel_key: vec![4; 32] };
        state.write_paired(&a).unwrap();
        assert_eq!(state.paired().unwrap(), Some(a));
        let b = PairedWith { chain: Vec::new(), account_root: vec![5; 32], channel_key: vec![6; 32] };
        state.write_paired(&b).unwrap();
        assert_eq!(state.paired().unwrap(), Some(b));
    }

    #[cfg(unix)]
    #[test]
    fn every_file_is_refused_once_others_can_read_it() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, state) = state();
        state.generate_keys().unwrap();
        state.allow(&[1; 32]).unwrap();
        state.add_root(tmp.path()).unwrap();
        for name in [IDENTITY_FILE, CALLERS_FILE, ROOTS_FILE] {
            let path = state.dir().join(name);
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "{name} written private");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert_eq!(state.keys().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(state.callers().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(state.roots().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn the_directory_is_created_private_and_an_existing_one_others_can_list_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, state) = state();
        state.generate_keys().unwrap();
        assert_eq!(fs::metadata(state.dir()).unwrap().permissions().mode() & 0o777, 0o700, "created 0700");

        fs::set_permissions(state.dir(), fs::Permissions::from_mode(0o755)).unwrap();
        for files in [0o600, 0o644] {
            for name in [IDENTITY_FILE, AGREEMENT_FILE] {
                fs::set_permissions(state.dir().join(name), fs::Permissions::from_mode(files)).unwrap();
            }
            let err = state.keys().unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "files {files:o}");
            assert!(err.to_string().contains("chmod 700"), "{err}");
        }
        assert_eq!(state.callers().unwrap_err().kind(), io::ErrorKind::PermissionDenied, "read refused");
        assert_eq!(state.allow(&[1; 32]).unwrap_err().kind(), io::ErrorKind::PermissionDenied, "write refused");
        assert!(!state.dir().join(CALLERS_FILE).exists(), "nothing written into it");

        // an existing directory, never created by the host, is refused the same way
        let (_tmp2, other) = super::tests::state();
        fs::create_dir(other.dir()).unwrap();
        fs::set_permissions(other.dir(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(other.generate_keys().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(!other.dir().join(IDENTITY_FILE).exists());
    }

    // --- the local roots ---

    #[test]
    fn no_roots_file_is_no_roots() {
        let (_tmp, state) = state();
        assert_eq!(state.roots().unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn a_root_is_kept_resolved_and_once() {
        let (tmp, state) = state();
        let real = fs::canonicalize(tmp.path()).unwrap();
        let work = real.join("work");
        fs::create_dir(&work).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&work, real.join("link")).unwrap();
        assert_eq!(state.add_root(&work).unwrap(), work);
        #[cfg(unix)]
        assert_eq!(state.add_root(&real.join("link")).unwrap(), work, "a symlink names its target");
        assert_eq!(state.roots().unwrap(), vec![work]);
    }

    #[test]
    fn a_bad_roots_line_is_an_error_naming_it_never_skipped() {
        let (tmp, state) = state();
        state.add_root(tmp.path()).unwrap();
        for (line, why) in [("relative/dir", "not an absolute path"), ("/no/such/dir/anywhere", "does not resolve")] {
            state
                .write_secret(ROOTS_FILE, format!("# comment\n{}\n{line}\n", tmp.path().display()).as_bytes(), true)
                .unwrap();
            let e = state.roots().unwrap_err();
            assert!(e.to_string().contains("line 3") && e.to_string().contains(why), "{e}");
        }
        let file = tmp.path().join("a-file");
        fs::write(&file, "").unwrap();
        state.write_secret(ROOTS_FILE, format!("{}\n", file.display()).as_bytes(), true).unwrap();
        assert!(state.roots().unwrap_err().to_string().contains("not a directory"));
    }

    // --- the local callers ---

    #[test]
    fn callers_start_empty_and_are_added_and_removed_at_this_machine() {
        let (_tmp, state) = state();
        assert!(state.callers().unwrap().is_empty(), "empty refuses everyone");
        assert!(state.allow(&[7; 32]).unwrap());
        assert!(!state.allow(&[7; 32]).unwrap(), "twice is once");
        assert!(state.allow(&[8; 32]).unwrap());
        assert_eq!(state.callers().unwrap().into_iter().collect::<Vec<_>>(), vec![[7; 32], [8; 32]]);
        assert!(state.disallow(&[7; 32]).unwrap());
        assert!(!state.disallow(&[7; 32]).unwrap());
        assert_eq!(state.callers().unwrap().into_iter().collect::<Vec<_>>(), vec![[8; 32]]);
    }

    #[test]
    fn a_bad_callers_line_is_an_error_naming_it() {
        let (_tmp, state) = state();
        state.allow(&[7; 32]).unwrap();
        state.write_secret(CALLERS_FILE, format!("{}\nnot-hex\n", hex(&[7; 32])).as_bytes(), true).unwrap();
        let e = state.callers().unwrap_err();
        assert!(e.to_string().contains("line 2"), "{e}");
    }

    #[test]
    fn hex_is_read_back_exactly() {
        assert_eq!(unhex(&hex(&[7u8; 32])), Some([7u8; 32]));
        assert_eq!(unhex(&hex(&[0u8; 31])), None);
        assert_eq!(unhex("g".repeat(64).as_str()), None);
    }
}
