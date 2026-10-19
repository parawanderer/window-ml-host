//! cli.rs — `wmlhost hub …`: pairing this host with a hub, and the two local files a remote caller cannot write (the
//! roots it may work in, and who may call at all). Run at this machine, by the person it belongs to.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use wmlhub_keys::{hex, principal_id, verify_chain};

use std::sync::Arc;

use wmlhub_client::{Client, Config};
use wmlhub_seal::ChannelKey;

use super::pair::{Offer, PAIRING_WINDOW, ROLE, check};
use super::serve::{MakeHost, Serving};
use super::state::{State, unhex};
use crate::session::Host;

#[derive(Parser)]
#[command(name = "wmlhost hub", about = "This host on a window.ml hub, as a desktop runtime")]
struct Cli {
    /// The state directory (default `$WMLHOST_HUB_DIR`, else `~/.config/wmlhost/hub`).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair with a hub: prints a code and a fingerprint to confirm on the account's phone.
    Pair {
        /// The hub's websocket URL.
        #[arg(long)]
        hub: String,
        /// What the phone shows this host as.
        #[arg(long, default_value = "desktop")]
        label: String,
        /// Replace an existing pairing (the keys, and so the principal, stay the same).
        #[arg(long)]
        again: bool,
    },
    /// Serve calls over the hub until the connection ends.
    Serve {
        /// The hub's websocket URL.
        #[arg(long)]
        hub: String,
        /// The name the hub gives itself in its challenge.
        #[arg(long)]
        hub_name: String,
    },
    /// Allow a principal (64 hex) to call this host. Nobody may until one is allowed.
    Allow { principal: String },
    /// Stop allowing a principal.
    Disallow { principal: String },
    /// The directories a caller over the hub may work in.
    Roots {
        #[command(subcommand)]
        command: RootsCommand,
    },
    /// What this host is on the hub: principal, account, certificate, roots, callers.
    Status,
}

#[derive(Subcommand)]
enum RootsCommand {
    /// Add a directory (resolved now; a caller may narrow within it, never widen it).
    Add { dir: PathBuf },
    /// List them.
    List,
}

/// `wmlhost hub <args>`; `args` starts after `hub`. Returns the exit code.
pub fn main(args: &[String]) -> i32 {
    let cli = match Cli::try_parse_from(std::iter::once("wmlhost hub".to_owned()).chain(args.iter().cloned())) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    let state = match cli.state_dir {
        Some(dir) => State::at(dir),
        None => match State::from_system() {
            Ok(s) => s,
            Err(e) => return fail(&e.to_string()),
        },
    };
    match cli.command {
        Command::Pair { hub, label, again } => {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(pair(&state, &hub, &label, again))
        }
        Command::Serve { hub, hub_name } => {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
            rt.block_on(serve(&state, hub, hub_name))
        }
        Command::Allow { principal } => match unhex(principal.trim()) {
            None => fail("a principal is 64 hex characters (the caller's `Principal` line)"),
            Some(id) => match state.allow(&id) {
                Ok(true) => ok(&format!("allowed {}", hex(&id))),
                Ok(false) => ok(&format!("{} was already allowed", hex(&id))),
                Err(e) => fail(&e.to_string()),
            },
        },
        Command::Disallow { principal } => match unhex(principal.trim()) {
            None => fail("a principal is 64 hex characters"),
            Some(id) => match state.disallow(&id) {
                Ok(true) => ok(&format!("no longer allowed: {}", hex(&id))),
                Ok(false) => ok(&format!("{} was not allowed", hex(&id))),
                Err(e) => fail(&e.to_string()),
            },
        },
        Command::Roots { command: RootsCommand::Add { dir } } => match state.add_root(&dir) {
            Ok(real) => ok(&format!("root {}", real.display())),
            Err(e) => fail(&format!("{}: {e}", dir.display())),
        },
        Command::Roots { command: RootsCommand::List } => match state.roots() {
            Ok(roots) => {
                for r in roots {
                    println!("{}", r.display());
                }
                0
            }
            Err(e) => fail(&e.to_string()),
        },
        Command::Status => status(&state),
    }
}

async fn pair(state: &State, hub: &str, label: &str, again: bool) -> i32 {
    match state.paired() {
        Ok(Some(_)) if !again => {
            return fail(&format!(
                "already paired: {} holds a certificate. `wmlhost hub status` says what it is, and `--again` replaces it",
                state.dir().display()
            ));
        }
        Ok(_) => {}
        Err(e) => return fail(&e.to_string()),
    }
    // The keys outlive a pairing: pairing again keeps the host the same principal, so the callers' grants stand.
    let keys = match state.keys() {
        Ok(Some(keys)) => keys,
        Ok(None) => match state.generate_keys() {
            Ok(keys) => keys,
            Err(e) => return fail(&format!("cannot write keys to {}: {e}", state.dir().display())),
        },
        Err(e) => return fail(&e.to_string()),
    };
    let offer = match Offer::new(&keys, label, now_ms()) {
        Ok(offer) => offer,
        Err(e) => return fail(&e.to_string()),
    };
    let mut left = match offer.leave(hub).await {
        Ok(left) => left,
        Err(e) => return fail(&e.to_string()),
    };
    println!("Pairing code   {}", offer.code());
    println!("Fingerprint    {}", offer.fingerprint());
    println!();
    println!("Type the code into the account's phone (or a device it lets pair), and confirm it shows the same");
    println!("fingerprint. If it shows a different one, refuse it: something between here and there is offering");
    println!("its own keys instead.");
    println!();
    println!("Waiting up to {} minutes...", PAIRING_WINDOW.as_secs() / 60);
    let paired = match left.answer(PAIRING_WINDOW, now_ms).await {
        Ok(paired) => paired,
        Err(e) => return fail(&e.to_string()),
    };
    if let Err(e) = state.write_paired(&paired) {
        return fail(&format!("paired, but cannot write {}: {e}", state.dir().display()));
    }
    println!();
    println!("Paired. Nobody may call this host until `wmlhost hub allow <principal>`, and no directory is");
    println!("reachable until `wmlhost hub roots add <dir>`.");
    status(state)
}

async fn serve(state: &State, url: String, hub_name: String) -> i32 {
    let (keys, paired) = match (state.keys(), state.paired()) {
        (Ok(Some(keys)), Ok(Some(paired))) => (keys, paired),
        (Err(e), _) | (_, Err(e)) => return fail(&e.to_string()),
        _ => return fail("not paired: `wmlhost hub pair --hub <url>` first"),
    };
    if let Err(e) = check(&keys, &paired, now_ms()) {
        return fail(&format!("{e}; `wmlhost hub pair --hub <url> --again`"));
    }
    let (Ok(account_root), Ok(channel_key)) =
        (<[u8; 32]>::try_from(paired.account_root.as_slice()), <[u8; 32]>::try_from(paired.channel_key.as_slice()))
    else {
        return fail("what pairing stored is not a key; pair it again");
    };
    let mut client = match Client::connect(Config {
        url,
        hub_name,
        identity: keys.identity,
        agreement: keys.agreement,
        chain: paired.chain,
        account_root,
        role: ROLE,
        invite: Vec::new(),
    })
    .await
    {
        Ok(client) => client,
        Err(e) => return fail(&format!("cannot log in to the hub: {e:?}")),
    };
    let make_host: Arc<MakeHost> = Arc::new(|transport| {
        let mut host = Host::from_system()?;
        host.transport = transport;
        Ok(host)
    });
    let mut serving = match Serving::new(state, account_root, ChannelKey::from_bytes(channel_key), make_host) {
        Ok(s) => s,
        Err(e) => return fail(&e.to_string()),
    };
    println!("Serving as {}", hex(&client.principal()));
    let e = serving.run(&mut client, &now_ms).await;
    fail(&format!("stopped serving: {e:?}"))
}

fn status(state: &State) -> i32 {
    let keys = match state.keys() {
        Ok(Some(keys)) => keys,
        Ok(None) => {
            println!("Paired         no. Run `wmlhost hub pair --hub <url>`");
            return 0;
        }
        Err(e) => return fail(&e.to_string()),
    };
    println!("Principal      {}", hex(&principal_id(&keys.identity.public())));
    match state.paired() {
        Ok(Some(paired)) => match <[u8; 32]>::try_from(paired.account_root.as_slice()) {
            Ok(root) => {
                println!("Account        {}", hex(&root));
                match verify_chain(&root, &paired.chain, now_ms()) {
                    Ok(v) => {
                        println!("Label          {}", v.leaf.label);
                        println!("Role           {:?}", v.leaf.role());
                        println!("Certificate    valid for {}", for_how_long(v.leaf.not_after_ms, now_ms()));
                    }
                    Err(e) => println!("Certificate    NOT USABLE: {e:?}; `wmlhost hub pair --hub <url> --again`"),
                }
            }
            Err(_) => return fail("the account root in this host's state is not a key; pair it again"),
        },
        Ok(None) => println!("Paired         no. Run `wmlhost hub pair --hub <url>`"),
        Err(e) => return fail(&e.to_string()),
    }
    match state.roots() {
        Ok(roots) if roots.is_empty() => println!("Roots          none: every call is refused (NotConfigured)"),
        Ok(roots) => {
            for (i, r) in roots.iter().enumerate() {
                println!("{}{}", if i == 0 { "Roots          " } else { "               " }, r.display());
            }
        }
        Err(e) => println!("Roots          UNREADABLE: {e}"),
    }
    match state.callers() {
        Ok(c) if c.is_empty() => println!("Callers        none: every caller is refused"),
        Ok(c) => {
            for (i, id) in c.iter().enumerate() {
                println!("{}{}", if i == 0 { "Callers        " } else { "               " }, hex(id));
            }
        }
        Err(e) => println!("Callers        UNREADABLE: {e}"),
    }
    0
}

/// Days and hours: what matters about an expiry is whether it is a problem this week.
fn for_how_long(not_after_ms: u64, now_ms: u64) -> String {
    let left = Duration::from_millis(not_after_ms.saturating_sub(now_ms)).as_secs();
    match (left / 86_400, (left % 86_400) / 3_600) {
        (0, 0) => "less than an hour".into(),
        (0, h) => format!("{h} h"),
        (d, h) => format!("{d} d {h} h"),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after 1970").as_millis() as u64
}

fn ok(line: &str) -> i32 {
    println!("{line}");
    0
}

fn fail(line: &str) -> i32 {
    eprintln!("wmlhost hub: {line}");
    1
}
