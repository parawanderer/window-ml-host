//! framing.rs — Chrome's native messaging framing: a 4-byte NATIVE-endian length, then that many bytes of UTF-8 JSON.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The most the host may send in one message: Chrome's limit for a message from a native host.
pub const MAX_OUT: usize = 1024 * 1024;
/// The most the host accepts in one message: Chrome's limit for a message to a native host.
pub const MAX_IN: usize = 64 * 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// A length prefix (read) or a body (write) over the limit.
    TooLarge {
        len: usize,
        max: usize,
    },
    /// The stream ended inside a length prefix or a body.
    Truncated,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "i/o error: {e}"),
            FrameError::TooLarge { len, max } => write!(f, "frame of {len} bytes exceeds the limit of {max}"),
            FrameError::Truncated => write!(f, "stream ended inside a frame"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Reads one frame of at most `max` bytes. `Ok(None)` is a clean end of input before any byte of a length prefix.
pub async fn read_frame_max<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0u8; 4];
    let mut got = 0;
    while got < prefix.len() {
        let n = r.read(&mut prefix[got..]).await?;
        if n == 0 {
            return if got == 0 { Ok(None) } else { Err(FrameError::Truncated) };
        }
        got += n;
    }
    let len = u32::from_ne_bytes(prefix) as usize;
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut body = vec![0u8; len];
    match r.read_exact(&mut body).await {
        Ok(_) => Ok(Some(body)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(FrameError::Truncated),
        Err(e) => Err(e.into()),
    }
}

/// Reads one frame sent to the host (at most [`MAX_IN`]).
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    read_frame_max(r, MAX_IN).await
}

/// Writes one frame of at most `max` bytes and flushes it.
pub async fn write_frame_max<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8], max: usize) -> Result<(), FrameError> {
    if body.len() > max {
        return Err(FrameError::TooLarge { len: body.len(), max });
    }
    let len =
        u32::try_from(body.len()).map_err(|_| FrameError::TooLarge { len: body.len(), max: u32::MAX as usize })?;
    w.write_all(&len.to_ne_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Writes one frame from the host (at most [`MAX_OUT`]).
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), FrameError> {
    write_frame_max(w, body, MAX_OUT).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    // --- framing ---

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_ne_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    /// Yields at most one byte per `poll_read`.
    struct OneByte<'a>(&'a [u8]);

    impl AsyncRead for OneByte<'_> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some((&b, rest)) = self.0.split_first() {
                if buf.remaining() > 0 {
                    buf.put_slice(&[b]);
                    self.0 = rest;
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn round_trip_json_body() {
        let body = br#"{"type":"ping","n":1}"#;
        let mut out = Vec::new();
        write_frame(&mut out, body).await.unwrap();
        let got = read_frame(&mut &out[..]).await.unwrap();
        assert_eq!(got.as_deref(), Some(&body[..]));
    }

    #[tokio::test]
    async fn round_trip_zero_length_body() {
        let mut out = Vec::new();
        write_frame(&mut out, b"").await.unwrap();
        assert_eq!(out, vec![0, 0, 0, 0]);
        let got = read_frame(&mut &out[..]).await.unwrap();
        assert_eq!(got, Some(vec![]));
    }

    #[tokio::test]
    async fn two_frames_back_to_back_then_eof() {
        let mut out = Vec::new();
        write_frame(&mut out, b"one").await.unwrap();
        write_frame(&mut out, b"second").await.unwrap();
        let mut r = &out[..];
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut r).await.unwrap().unwrap(), b"second");
        assert!(read_frame(&mut r).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn clean_eof_on_empty_input_is_none() {
        assert!(read_frame(&mut &[][..]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn eof_inside_prefix_is_truncated() {
        let r = read_frame(&mut &[1u8, 0][..]).await;
        assert!(matches!(r, Err(FrameError::Truncated)));
    }

    #[tokio::test]
    async fn eof_inside_body_is_truncated() {
        let mut data = 10u32.to_ne_bytes().to_vec();
        data.extend_from_slice(b"abc");
        let r = read_frame(&mut &data[..]).await;
        assert!(matches!(r, Err(FrameError::Truncated)));
    }

    #[tokio::test]
    async fn oversized_prefix_is_too_large_without_body() {
        let data = ((MAX_IN + 1) as u32).to_ne_bytes();
        match read_frame(&mut &data[..]).await {
            Err(FrameError::TooLarge { len, max }) => {
                assert_eq!(len, MAX_IN + 1);
                assert_eq!(max, MAX_IN);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_limit_is_inclusive_and_writes_nothing_over() {
        let mut out = Vec::new();
        write_frame(&mut out, &vec![b'x'; MAX_OUT]).await.unwrap();
        assert_eq!(out.len(), 4 + MAX_OUT);

        let mut out = Vec::new();
        let r = write_frame(&mut out, &vec![b'x'; MAX_OUT + 1]).await;
        assert!(matches!(r, Err(FrameError::TooLarge { .. })));
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn prefix_is_native_endian() {
        let body = vec![b'a'; 0x0102];
        let mut out = Vec::new();
        write_frame(&mut out, &body).await.unwrap();
        assert_eq!(out[..4], (body.len() as u32).to_ne_bytes());
    }

    #[tokio::test]
    async fn one_byte_per_poll_reader_decodes() {
        let data = framed(br#"{"slow":true}"#);
        let got = read_frame(&mut OneByte(&data)).await.unwrap();
        assert_eq!(got.as_deref(), Some(&br#"{"slow":true}"#[..]));
    }
}
