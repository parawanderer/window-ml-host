//! framing.rs — Chrome's native messaging framing: a 4-byte NATIVE-endian length, then that many bytes of UTF-8 JSON.

use tokio::io::{AsyncRead, AsyncWrite};

/// The most the host may send in one message: Chrome's limit for a message from a native host.
pub const MAX_OUT: usize = 1024 * 1024;
/// The most the host accepts in one message: Chrome's limit for a message to a native host.
pub const MAX_IN: usize = 64 * 1024 * 1024;

/// Why a frame could not be read or written.
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// A length prefix (read) or a body (write) over the limit.
    TooLarge { len: usize, max: usize },
    /// The stream ended inside a length prefix or a body.
    Truncated,
}

/// Reads one frame of at most `max` bytes. `Ok(None)` is a clean end of input before any byte of a length prefix.
pub async fn read_frame_max<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let _ = (r, max);
    todo!()
}

/// Reads one frame sent to the host (at most [`MAX_IN`]).
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    read_frame_max(r, MAX_IN).await
}

/// Writes one frame of at most `max` bytes and flushes it.
pub async fn write_frame_max<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8], max: usize) -> Result<(), FrameError> {
    let _ = (w, body, max);
    todo!()
}

/// Writes one frame from the host (at most [`MAX_OUT`]).
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), FrameError> {
    write_frame_max(w, body, MAX_OUT).await
}
