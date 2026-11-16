//! Codecs behind a cargo feature, each with a stub that reports it unavailable when off.

#[cfg(any(
    feature = "codec-bzip2",
    feature = "codec-zstd",
    feature = "codec-brotli"
))]
use std::io::Read;

#[cfg(any(
    feature = "codec-bzip2",
    feature = "codec-zstd",
    feature = "codec-brotli"
))]
use snafu::{ResultExt, ensure};

use super::{DecodeError, decode_error};
use crate::wire::Compression;

#[cfg(any(
    feature = "codec-bzip2",
    feature = "codec-zstd",
    feature = "codec-brotli"
))]
/// Reads a decoder to its end, failing rather than truncating past `limit`.
///
/// `take(limit)` alone stops at the ceiling and reports the truncated output
/// as clean, which lets an oversized stream through. Taking one byte more and
/// refusing it turns the ceiling into an error.
fn bounded(id: Compression, reader: impl Read, limit: usize) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut out)
        .context(decode_error::Decompress { id })?;
    ensure!(out.len() <= limit, decode_error::TooLarge { id, limit });
    Ok(out)
}

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

#[cfg(test)]
mod tests {
    /// The process's peak virtual size, which moves for C allocations the counting allocator cannot see.
    #[cfg(all(target_os = "linux", feature = "codec-zstd"))]
    fn vm_peak() -> usize {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("VmPeak:")).unwrap();
        let kib: usize = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        kib << 10
    }

    /// Found by the `codec_zstd` fuzz target: a 10-byte frame declaring a 128 MiB window and no content size.
    #[cfg(all(target_os = "linux", feature = "codec-zstd"))]
    #[test]
    fn a_zstd_window_cannot_reserve_past_the_output_limit() {
        use assert2::check;

        use crate::codec::{Expect, decode};
        use crate::tests::kit::MIB;
        use crate::wire::Compression;
        let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x09, 0x00, 0x00, b'A'];
        let expect = Expect {
            declared: None,
            limit: 64 << 10,
        };
        let before = vm_peak();
        // Upstream never writes a window past its content, so refusing the frame is as good as decoding it.
        let got = decode(Compression::ZSTD, &frame, expect);
        check!(got.as_deref().map_or(true, |out| out == b"A"));
        let grew = vm_peak().saturating_sub(before);
        check!(
            grew < 16 * MIB,
            "decoding one byte under a 64 KiB limit grew the process by {grew} bytes"
        );
    }

    /// Two brotli streams whose windows dwarf what they decode to.
    ///
    /// The first has the largest standard window, its data split over two
    /// metablocks so the decoder cannot size down. The second, found by the
    /// `codec_brotli` fuzz target, opens with the large-window signature `0x11`.
    #[cfg(feature = "codec-brotli")]
    #[test]
    fn a_brotli_window_stays_within_the_standard_maximum() {
        use std::io::Write;

        use assert2::check;

        use crate::codec::{Expect, decode};
        use crate::tests::alloc::peak;
        use crate::tests::kit::MIB;
        use crate::wire::Compression;
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 1, 24);
        encoder.write_all(b"first metablock").unwrap();
        encoder.flush().unwrap();
        encoder.write_all(b", then a second").unwrap();
        let standard = encoder.into_inner();
        let large: Vec<u8> = std::iter::once(0x11)
            .chain(std::iter::repeat_n(0x1D, 122))
            .collect();
        let over: Vec<String> = [(standard, None), (large, Some(53_098))]
            .into_iter()
            .filter_map(|(stream, declared)| {
                let expect = Expect {
                    declared,
                    limit: 64 << 10,
                };
                let (_, held) = peak(|| decode(Compression::BROTLI, &stream, expect));
                // 16 MiB is the largest window standard brotli can name.
                (held > 17 * MIB).then(|| {
                    format!(
                        "a {}-byte stream under a 64 KiB limit held {held} bytes",
                        stream.len()
                    )
                })
            })
            .collect();
        check!(over.is_empty(), "{}", over.join("\n"));
    }
}
