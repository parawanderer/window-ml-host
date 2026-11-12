//! The CONNECT proxy a credentialed call reaches the network through. On macOS the call's Seatbelt profile allows one
//! outbound address, this listener's `localhost:<port>`. On Linux the call has no network at all (`--unshare-net`): the
//! proxy listens on a unix socket bound into the sandbox, and `wmlhost forward` (src/exec_under.rs) carries the call's
//! `127.0.0.1:<IN_SANDBOX_PORT>` to it. Either way the proxy admits only `CONNECT <listed host>:<listed port>` and then
//! splices bytes. It never terminates TLS, so the token passes through nothing it parses. One proxy per call, closed
//! when the call ends (dropping [`Proxy`] aborts the listener and every connection, and removes its socket).

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::task::{JoinHandle, JoinSet};

/// The most a request head may be, its headers included.
pub const MAX_HEAD: usize = 8 * 1024;
/// How long a client has to send its request head.
pub const HEAD_DEADLINE: Duration = Duration::from_secs(10);
/// How long the upstream connect may take.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// The most connections one call may hold open at once; a further one is closed unanswered.
pub const MAX_CONNS: usize = 64;

/// The port a Linux call's forwarder listens on inside the sandbox. Its network namespace is its own and empty, so
/// one fixed port collides with nothing.
pub const IN_SANDBOX_PORT: u16 = 18443;

/// A running proxy. Dropping it closes the listener and every connection it holds.
pub struct Proxy {
    /// The port the call connects to: this listener's on macOS, [`IN_SANDBOX_PORT`] for a unix-socket proxy.
    pub port: u16,
    /// The unix socket a Linux call's forwarder reaches this proxy on.
    pub socket: Option<PathBuf>,
    task: JoinHandle<()>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
        if let Some(s) = &self.socket {
            let _ = std::fs::remove_file(s);
        }
    }
}

/// A listener the proxy accepts on: TCP on macOS, a unix socket on Linux.
trait Accept: Send + 'static {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn next(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

impl Accept for TcpListener {
    type Stream = TcpStream;
    async fn next(&self) -> io::Result<TcpStream> {
        self.accept().await.map(|(s, _)| s)
    }
}

impl Accept for UnixListener {
    type Stream = tokio::net::UnixStream;
    async fn next(&self) -> io::Result<tokio::net::UnixStream> {
        self.accept().await.map(|(s, _)| s)
    }
}

/// Starts a proxy on `127.0.0.1:<ephemeral>` that admits `hosts` on `ports`. Must be called inside the tokio runtime.
pub fn start(hosts: Vec<&'static str>, ports: Vec<u16>) -> io::Result<Proxy> {
    let std = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    std.set_nonblocking(true)?;
    let port = std.local_addr()?.port();
    let listener = TcpListener::from_std(std)?;
    Ok(Proxy { port, socket: None, task: accept_loop(listener, hosts, ports) })
}

/// Starts a proxy on the unix socket `path` (which must not exist; its directory is the call's own, 0700) that admits
/// `hosts` on `ports`. Must be called inside the tokio runtime.
pub fn start_unix(path: &Path, hosts: Vec<&'static str>, ports: Vec<u16>) -> io::Result<Proxy> {
    let listener = UnixListener::bind(path)?;
    Ok(Proxy { port: IN_SANDBOX_PORT, socket: Some(path.to_path_buf()), task: accept_loop(listener, hosts, ports) })
}

fn accept_loop<L: Accept>(listener: L, hosts: Vec<&'static str>, ports: Vec<u16>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            let Ok(client) = listener.next().await else { continue };
            while conns.try_join_next().is_some() {}
            if conns.len() >= MAX_CONNS {
                drop(client);
                continue;
            }
            let (hosts, ports) = (hosts.clone(), ports.clone());
            conns.spawn(async move {
                let _ = serve(client, &hosts, &ports).await;
            });
        }
    })
}

/// One client connection: read the head, admit or refuse it, then splice.
async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut client: S, hosts: &[&str], ports: &[u16]) -> io::Result<()> {
    let Ok(Ok((head, rest))) = tokio::time::timeout(HEAD_DEADLINE, read_head(&mut client)).await else {
        return Ok(());
    };
    let Some((host, port)) = admit(&head, hosts, ports) else {
        return client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    };
    // The listed NAME is resolved with the host's own resolver: the bound is the name, not an address.
    let upstream = match tokio::time::timeout(CONNECT_DEADLINE, TcpStream::connect((host, port))).await {
        Ok(Ok(u)) => u,
        _ => {
            return client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        }
    };
    let mut upstream = upstream;
    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
    // Bytes the client sent past the head (a ClientHello it did not wait to send) go first.
    upstream.write_all(&rest).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Reads up to the end of the request head (`\r\n\r\n`), at most [`MAX_HEAD`] bytes. Returns the head and whatever
/// followed it in the same reads.
async fn read_head<S: AsyncRead + Unpin>(c: &mut S) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((buf, rest));
        }
        if buf.len() >= MAX_HEAD {
            return Err(io::Error::other("request head too large"));
        }
        let n = c.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::other("closed before the head ended"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The upstream a request head may reach, or `None`. Only the request line counts; headers are ignored. It must be
/// exactly `CONNECT <name>:<port> HTTP/1.x` with `<name>` one of `hosts` (ASCII-lowercased, one trailing dot dropped)
/// and `<port>` one of `ports`. Anything else, an IP literal, userinfo, an escape or another method, is refused,
/// because no listed name contains those characters.
pub fn admit<'a>(head: &[u8], hosts: &[&'a str], ports: &[u16]) -> Option<(&'a str, u16)> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line.strip_suffix(b"\r")?).ok()?;
    let mut parts = line.split(' ');
    let (Some("CONNECT"), Some(authority), Some("HTTP/1.1" | "HTTP/1.0"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let (name, port) = authority.rsplit_once(':')?;
    if port.is_empty() || port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) || port.len() > 5 {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if !ports.contains(&port) {
        return None;
    }
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let host = hosts.iter().find(|h| **h == name)?;
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTS: &[&str] = &["api.github.com", "github.com"];

    fn a(line: &str) -> Option<(&'static str, u16)> {
        admit(format!("{line}\r\nHost: x\r\n\r\n").as_bytes(), HOSTS, &[443])
    }

    // --- what the request line admits ---

    #[test]
    fn a_listed_name_on_a_listed_port_is_admitted_in_any_case_and_with_one_trailing_dot() {
        assert_eq!(a("CONNECT api.github.com:443 HTTP/1.1"), Some(("api.github.com", 443)));
        assert_eq!(a("CONNECT GITHUB.COM.:443 HTTP/1.1"), Some(("github.com", 443)));
        assert_eq!(a("CONNECT github.com:443 HTTP/1.0"), Some(("github.com", 443)));
    }

    #[test]
    fn every_spoofed_authority_is_refused() {
        for line in [
            "CONNECT example.com:443 HTTP/1.1",
            "CONNECT github.com.evil.test:443 HTTP/1.1",
            "CONNECT evil.test#@github.com:443 HTTP/1.1",
            "CONNECT github.com@evil.test:443 HTTP/1.1",
            "CONNECT user@github.com:443 HTTP/1.1",
            "CONNECT github.com..:443 HTTP/1.1",
            "CONNECT 140.82.112.3:443 HTTP/1.1",
            "CONNECT [::1]:443 HTTP/1.1",
            "CONNECT %67ithub.com:443 HTTP/1.1",
            "CONNECT github.com:80 HTTP/1.1",
            "CONNECT github.com:0443 HTTP/1.1",
            "CONNECT github.com:+443 HTTP/1.1",
            "CONNECT github.com: HTTP/1.1",
            "CONNECT github.com HTTP/1.1",
            "CONNECT github.com:443:443 HTTP/1.1",
            "CONNECT  github.com:443 HTTP/1.1",
            "CONNECT github.com:443 HTTP/2",
            "CONNECT github.com:443",
            "CONNECT github.com:443 HTTP/1.1 x",
            "connect github.com:443 HTTP/1.1",
            "GET http://github.com/ HTTP/1.1",
            "GET / HTTP/1.1",
            "CONNECT ɡithub.com:443 HTTP/1.1",
        ] {
            assert_eq!(a(line), None, "{line}");
        }
    }

    #[test]
    fn a_head_without_crlf_or_with_a_bare_lf_is_refused() {
        assert_eq!(admit(b"CONNECT github.com:443 HTTP/1.1\n\n", HOSTS, &[443]), None);
        assert_eq!(admit(b"CONNECT github.com:443 HTTP/1.1", HOSTS, &[443]), None);
    }

    #[test]
    fn only_the_request_line_counts_not_a_host_header() {
        let h = b"CONNECT example.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n";
        assert_eq!(admit(h, HOSTS, &[443]), None);
    }

    // --- the listener ---

    async fn ask(port: u16, head: &[u8]) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(head).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn an_unlisted_host_gets_403_and_no_upstream_connection() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up.local_addr().unwrap().port();
        let p = start(vec!["localhost"], vec![up_port]).unwrap();
        let r = ask(p.port, format!("CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n\r\n").as_bytes()).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        let r = ask(p.port, format!("GET http://localhost:{up_port}/ HTTP/1.1\r\n\r\n").as_bytes()).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), up.accept()).await.is_err(),
            "the upstream was reached"
        );
    }

    #[tokio::test]
    async fn a_listed_host_is_spliced_both_ways_with_early_bytes_first() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        });
        let p = start(vec!["localhost"], vec![up_port]).unwrap();
        let r = ask(p.port, format!("CONNECT localhost:{up_port} HTTP/1.1\r\n\r\nhello").as_bytes()).await;
        assert_eq!(r, "HTTP/1.1 200 Connection established\r\n\r\nhello");
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn an_oversized_head_is_dropped_unanswered() {
        let p = start(vec!["github.com"], vec![443]).unwrap();
        let mut head = b"CONNECT github.com:443 HTTP/1.1\r\nX: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        let r = ask(p.port, &head).await;
        assert_eq!(r, "", "an oversized head got an answer");
    }

    #[tokio::test]
    async fn a_unix_socket_proxy_admits_and_refuses_as_the_tcp_one_and_removes_its_socket_when_dropped() {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = up.local_addr().unwrap().port();
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("p.sock");
        let p = start_unix(&sock, vec!["localhost"], vec![up_port]).unwrap();
        assert_eq!(p.port, IN_SANDBOX_PORT);
        let ask_unix = |head: String| {
            let sock = sock.clone();
            async move {
                let mut c = tokio::net::UnixStream::connect(&sock).await.unwrap();
                c.write_all(head.as_bytes()).await.unwrap();
                let mut out = vec![0u8; 64];
                let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut out)).await.unwrap().unwrap();
                String::from_utf8_lossy(&out[..n]).into_owned()
            }
        };
        let r = ask_unix("CONNECT example.com:443 HTTP/1.1\r\n\r\n".into()).await;
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        let r = ask_unix(format!("CONNECT localhost:{up_port} HTTP/1.1\r\n\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        drop(p);
        assert!(!sock.exists(), "the socket outlived its proxy");
    }

    #[tokio::test]
    async fn dropping_the_proxy_closes_its_listener() {
        let p = start(vec!["github.com"], vec![443]).unwrap();
        let port = p.port;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());
        drop(p);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err(), "the listener outlived its call");
    }
}
