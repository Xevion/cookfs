//! The shared decode loop and the deflate decoder built on it.

use snafu::{ResultExt, ensure};

use super::{DecodeError, decode_error};
use crate::wire::Compression;

/// What one decoder step reported.
pub(super) enum Step {
    /// Made progress or may with more room; call again.
    Going,
    /// The stream ended cleanly.
    Done,
    /// No progress is possible: input ran out before the stream ended.
    Starved,
}

/// The most a decode reserves per byte of compressed input before its output shows it needs more.
///
/// Real pages compress a few times over; the declared or recorded size is what
/// the archive claims, so a crafted 10-byte page claiming 1 GiB would otherwise
/// reserve that much up front.
const RESERVE_RATIO: usize = 1024;
/// The least a decode reserves, and the least it grows by.
const MIN_RESERVE: usize = 64 << 10;

/// Runs a decoder that writes into a `Vec`'s spare capacity, until it ends or `target` bytes are out.
///
/// Decoding straight into the output skips the doubling and zero-filling a
/// `read_to_end` pays per page. `hint` sizes the first reservation; growth is
/// exact, so the output never holds more than `target` bytes.
pub(super) fn drain(
    id: Compression,
    input_len: usize,
    hint: usize,
    target: usize,
    mut step: impl FnMut(&mut Vec<u8>) -> std::io::Result<Step>,
) -> Result<Vec<u8>, DecodeError> {
    let reserve = hint
        .min(input_len.saturating_mul(RESERVE_RATIO).max(MIN_RESERVE))
        .min(target);
    let mut out = Vec::with_capacity(reserve);
    while out.len() < target {
        if out.len() == out.capacity() {
            // `with_capacity` is exact for bytes, so the decoder can never write past `target`.
            let mut grown =
                Vec::with_capacity(out.len().saturating_mul(2).max(MIN_RESERVE).min(target));
            grown.extend_from_slice(&out);
            out = grown;
        }
        match step(&mut out).context(decode_error::Decompress { id })? {
            Step::Done => break,
            Step::Starved if out.len() < out.capacity() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream ends before its data does",
                ))
                .context(decode_error::Decompress { id });
            }
            // A starved step with no room left only needs the room grown above.
            Step::Going | Step::Starved => {}
        }
    }
    Ok(out)
}

/// Raw deflate, decoded straight into its output.
pub(super) fn deflate(
    id: Compression,
    body: &[u8],
    limit: usize,
    declared: Option<usize>,
) -> Result<Vec<u8>, DecodeError> {
    let mut inflate = flate2::Decompress::new(false);
    let target = limit.saturating_add(1);
    let out = drain(id, body.len(), declared.unwrap_or(limit), target, |out| {
        let consumed = usize::try_from(inflate.total_in()).unwrap_or(usize::MAX);
        let input = body.get(consumed..).unwrap_or_default();
        let status = inflate
            .decompress_vec(input, out, flate2::FlushDecompress::None)
            .map_err(std::io::Error::other)?;
        Ok(match status {
            flate2::Status::StreamEnd => Step::Done,
            flate2::Status::BufError => Step::Starved,
            flate2::Status::Ok => Step::Going,
        })
    })?;
    ensure!(out.len() <= limit, decode_error::TooLarge { id, limit });
    Ok(out)
}
