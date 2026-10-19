//! main.rs — the `wmlhost` binary: started by the browser with the calling extension's origin as its argument, it
//! serves the protocol on stdio; `wmlhost install` registers it with the browser.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("install") | Some("uninstall") => std::process::exit(window_ml_host::install::main(&args[1..])),
        Some("warden") => std::process::exit(window_ml_host::owners::warden_main(&args[2..])),
        Some("--version") | Some("-V") => println!("wmlhost {}", env!("CARGO_PKG_VERSION")),
        // Chrome passes `chrome-extension://<id>/` (and on Windows a window handle); `serve` is for tests and humans.
        _ => std::process::exit(serve()),
    }
}

/// Serves one session on stdin/stdout. stdout carries ONLY protocol frames: anything else goes to stderr, which Chrome
/// writes to its own log.
fn serve() -> i32 {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");
    rt.block_on(async {
        let host = match window_ml_host::session::Host::from_system() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("wmlhost: cannot create the session directory: {e}");
                return 1;
            }
        };
        match window_ml_host::session::serve(tokio::io::stdin(), tokio::io::stdout(), host).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("wmlhost: {e}");
                1
            }
        }
    })
}
