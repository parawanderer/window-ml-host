//! main.rs — the `wmlhost` binary: started by the browser with the calling extension's origin as its argument, it
//! serves the protocol on stdio; `wmlhost install` registers it with the browser.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("install") | Some("uninstall") => std::process::exit(window_ml_host::install::main(&args[1..])),
        Some("--version") | Some("-V") => println!("wmlhost {}", env!("CARGO_PKG_VERSION")),
        _ => {
            eprintln!("wmlhost: serving is not built yet");
            std::process::exit(2);
        }
    }
}
