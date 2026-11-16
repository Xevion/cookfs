//! Codecs behind a cargo feature, each with a stub that reports it unavailable when off.

#[cfg(any(feature = "codec-zstd", feature = "codec-brotli"))]
use snafu::ResultExt;

#[cfg(any(
    feature = "codec-bzip2",
    feature = "codec-zstd",
    feature = "codec-brotli"
))]
use super::bounded;
use super::{DecodeError, decode_error};
use crate::wire::Compression;

#[cfg(feature = "codec-bzip2")]
pub(super) fn bzip2(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
    bounded(id, bzip2::read::BzDecoder::new(body), limit)
}

#[cfg(not(feature = "codec-bzip2"))]
pub(super) fn bzip2(id: Compression, _: &[u8], _: usize) -> Result<Vec<u8>, DecodeError> {
    decode_error::Unavailable {
        id,
        why: "the `codec-bzip2` feature is off",
    }
    .fail()
}

#[cfg(feature = "codec-zstd")]
/// Decodes a zstd frame whose window is no larger than the output it may produce.
///
/// The decoder allocates the window the frame header asks for, up to 128 MiB
/// from a 10-byte frame. Upstream writes single-segment frames, whose window
/// is their content size, so capping it at the output limit refuses only
/// frames no upstream writer produces.
pub(super) fn zstd(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
    const MIN_WINDOW_LOG: u32 = 10;
    const MAX_WINDOW_LOG: u32 = 31;
    let window_log = limit
        .checked_next_power_of_two()
        .map_or(MAX_WINDOW_LOG, usize::trailing_zeros)
        .clamp(MIN_WINDOW_LOG, MAX_WINDOW_LOG);
    let mut decoder =
        zstd::stream::read::Decoder::new(body).context(decode_error::Decompress { id })?;
    decoder
        .window_log_max(window_log)
        .context(decode_error::Decompress { id })?;
    bounded(id, decoder, limit)
}

#[cfg(not(feature = "codec-zstd"))]
pub(super) fn zstd(id: Compression, _: &[u8], _: usize) -> Result<Vec<u8>, DecodeError> {
    decode_error::Unavailable {
        id,
        why: "the `codec-zstd` feature is off",
    }
    .fail()
}

#[cfg(feature = "codec-brotli")]
/// Decodes a standard brotli stream, whose window is at most 16 MiB.
///
/// The decoder also accepts the large-window extension, which upstream's
/// decoder refuses and which lets a 123-byte stream claim a 512 MiB window.
/// Its first seven bits are a fixed marker, so it is refused before decoding.
pub(super) fn brotli(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
    const BUFFER: usize = 4096;
    const LARGE_WINDOW: u8 = 0x11;
    if body.first().is_some_and(|b| b & 0x7F == LARGE_WINDOW) {
        return Err(std::io::Error::other(
            "large-window brotli is not standard brotli",
        ))
        .context(decode_error::Decompress { id });
    }
    bounded(id, brotli::Decompressor::new(body, BUFFER), limit)
}

#[cfg(not(feature = "codec-brotli"))]
pub(super) fn brotli(id: Compression, _: &[u8], _: usize) -> Result<Vec<u8>, DecodeError> {
    decode_error::Unavailable {
        id,
        why: "the `codec-brotli` feature is off",
    }
    .fail()
}
