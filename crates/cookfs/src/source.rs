//! Reads from the random-access source an archive is opened over.
//!
//! Neither format has a header at the front of the file. A reader locates the
//! archive by scanning backward for a trailer signature and walking each
//! format's own length-prefixed fields outward from there.

use positioned_io::ReadAt;
use snafu::{ResultExt, Snafu};

/// A failure reading the source itself.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum SourceError {
    /// A read past the source's end, or a failure below it.
    #[snafu(display("read of {len} bytes at offset {offset} failed"))]
    Io {
        /// Offset the read started at.
        offset: u64,
        /// Bytes the read asked for.
        len: usize,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The source cannot report its length, so no scan can start.
    #[snafu(display("source has no known length"))]
    NoLength,
}

const _: () = assert!(size_of::<SourceError>() <= 64);

/// Reads exactly `len` bytes at `offset`.
pub(crate) fn at<R: ReadAt>(src: &R, offset: u64, len: usize) -> Result<Vec<u8>, SourceError> {
    let mut buf = vec![0u8; len];
    src.read_exact_at(offset, &mut buf)
        .context(source_error::Io { offset, len })?;
    Ok(buf)
}

/// Signature hits a scan rejects before it stops looking.
const MAX_CANDIDATES: usize = 4096;

/// Scans backward for any of `signatures`, returning the rightmost hit `validate` accepts.
///
/// A hit is not necessarily the archive: an installer can append other layers
/// (a Metakit database, a code-signing certificate) that contain the same
/// bytes, so `validate` should check the trailer is plausible. It runs once per
/// hit, so it must cost a few small reads, not a parse. The scan gives up after
/// [`MAX_CANDIDATES`] rejected hits, so a file packed with signatures costs no
/// more than that. Every signature must share one length, which holds for
/// `CFS0002` and `CFS0003`.
pub(crate) fn find_signature<R: ReadAt>(
    src: &R,
    len: u64,
    signatures: &[&[u8]],
    mut validate: impl FnMut(u64, usize) -> bool,
) -> Result<Option<(u64, usize)>, SourceError> {
    const WINDOW: u64 = 1 << 20;

    let Some(sig_len) = signatures.first().map(|s| s.len()).filter(|&n| n > 0) else {
        return Ok(None);
    };

    let mut rejected = 0;
    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(WINDOW);
        // Overlap the next window by one signature so a hit straddling the seam is seen.
        let span_len = ((len - start) as usize).min((end - start) as usize + sig_len - 1);
        let span = at(src, start, span_len)?;

        for i in (0..span.len().saturating_sub(sig_len - 1)).rev() {
            for (idx, sig) in signatures.iter().enumerate() {
                if span[i..i + sig_len] == **sig {
                    let candidate = start + i as u64;
                    if validate(candidate, idx) {
                        return Ok(Some((candidate, idx)));
                    }
                    rejected += 1;
                    if rejected == MAX_CANDIDATES {
                        return Ok(None);
                    }
                }
            }
        }
        end = start;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::{assert, check};

    const SIG_A: &[u8] = b"AAAAAAA";
    const SIG_B: &[u8] = b"BBBBBBB";

    #[test]
    fn a_short_read_reports_the_offset_and_length() {
        let buf: &[u8] = b"short";
        check!(let Err(SourceError::Io { offset: 0, len: 100, .. }) = at(&buf, 0, 100));
    }

    #[test]
    fn the_rightmost_candidate_that_validates_wins_over_a_decoy() {
        let mut buf = vec![0xFFu8; 20];
        buf.extend_from_slice(SIG_A);
        buf.extend_from_slice(&[0xAAu8; 10]);
        let real = buf.len() as u64;
        buf.extend_from_slice(SIG_B);

        let found = find_signature(
            &buf.as_slice(),
            buf.len() as u64,
            &[SIG_A, SIG_B],
            |_, idx| idx == 1,
        );
        assert!(let Ok(Some((hit, 1))) = found);
        check!(hit == real);
    }

    #[test]
    fn nothing_that_validates_is_none() {
        let mut buf = vec![0u8; 20];
        buf.extend_from_slice(SIG_A);
        let found = find_signature(&buf.as_slice(), buf.len() as u64, &[SIG_A], |_, _| false);
        check!(let Ok(None) = found);
    }

    #[test]
    fn the_scan_stops_after_too_many_rejected_candidates() {
        let mut buf = SIG_A.to_vec();
        buf.extend(SIG_A.repeat(MAX_CANDIDATES));
        let mut calls = 0;
        let found = find_signature(&buf.as_slice(), buf.len() as u64, &[SIG_A], |at, _| {
            calls += 1;
            at == 0
        });
        check!(let Ok(None) = found);
        check!(calls == MAX_CANDIDATES);
    }

    #[test]
    fn a_signature_straddling_two_windows_is_found() {
        let mut buf = vec![0u8; (1 << 20) - 3];
        let real = buf.len() as u64;
        buf.extend_from_slice(SIG_A);
        buf.extend_from_slice(&vec![0u8; 1 << 20]);
        let found = find_signature(&buf.as_slice(), buf.len() as u64, &[SIG_A], |_, _| true);
        assert!(let Ok(Some((hit, 0))) = found);
        check!(hit == real);
    }
}
