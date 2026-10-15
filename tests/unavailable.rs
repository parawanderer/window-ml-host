//! unavailable.rs — the fail-closed path on every platform: a session whose sandbox is unavailable says so in every
//! fact (`sandboxed: false`, `placement: "host-plain"`), and spawns nothing without an explicit `start`.

use std::sync::Arc;

use serde_json::{Value, json};
use window_ml_host::env::NoSecrets;
use window_ml_host::framing::{read_frame_max, write_frame_max};
use window_ml_host::sandbox::Availability;
use window_ml_host::session::{Host, serve};
use window_ml_host::store::Store;

#[tokio::test]
async fn an_unavailable_sandbox_is_reported_and_nothing_runs_without_start() {
    let base = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let r = root.path().canonicalize().unwrap();
    let host = Host {
        sandbox: Availability { kind: None, program: None, available: false, reason: Some("test".into()) },
        secrets: Box::new(NoSecrets),
        store: Arc::new(Store::create(base.path()).unwrap()),
        host_env: Box::new(|k| std::env::var(k).ok()),
    };
    let (mut ours, theirs) = tokio::io::duplex(1 << 20);
    let (rd, wr) = tokio::io::split(theirs);
    let server = tokio::spawn(serve(rd, wr, host));
    let mut call = async |seq: u64, name: &str, args: Value| -> Value {
        let b = serde_json::to_vec(&json!({ "seq": seq, "call": name, "args": args })).unwrap();
        write_frame_max(&mut ours, &b, usize::MAX).await.unwrap();
        let f = read_frame_max(&mut ours, 1 << 20).await.unwrap().unwrap();
        serde_json::from_slice(&f).unwrap()
    };
    let h = call(1, "hello", json!({})).await;
    assert_eq!(h["value"]["sandbox"]["available"], false);
    let c = call(2, "configure", json!({ "roots": [r] })).await;
    assert_eq!(c["value"]["sandboxed"], false, "asked for, not available: reported");
    let f = call(3, "spawn", json!({ "argv": ["touch", "marker"], "cwd": r })).await;
    assert_eq!(f["value"]["sandboxed"], false);
    assert_eq!(f["value"]["placement"], "host-plain");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!r.join("marker").exists(), "nothing runs without start");
    drop(ours);
    server.await.unwrap().unwrap();
}
