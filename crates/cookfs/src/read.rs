//! Low-level byte access and signature scanning shared by every cookfs format.
//!
//! Neither `CFS0002` nor `CFS0003` has a header at the front of the file:
//! readers locate the archive by scanning backward for a trailer signature and
//! walking each format's own length-prefixed fields outward from there. What a
//! valid trailer looks like is format-specific and lives in `parsers`; this
//! module only knows how to read bytes and how to scan for a signature once
//! told what one looks like.

use positioned_io::ReadAt;
use snafu::{OptionExt, ResultExt, Snafu};

/// The magic bytes that open a decompressed fsindex blob, identical across
/// every format this crate reads.
pub const FSINDEX_MAGIC: &[u8] = b"CFS2.200";

/// Everything that can go wrong reading a cookfs archive.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    /// A read past the source's own bounds, or a filesystem-level failure.
    #[snafu(display("read failed at {offset}"))]
    Io {
        /// Byte offset the read was attempted at.
        offset: u64,
        /// Underlying I/O failure.
        source: std::io::Error,
    },
    /// The source cannot report its own length, so scanning cannot start.
    #[snafu(display("source has no known length"))]
    NoLength,
    /// No known cookfs signature (`CFS0002` or `CFS0003`) parsed as a trailer
    /// anywhere in the source.
    #[snafu(display("no cookfs signature found"))]
    NoSignature,
    /// A trailer's length-prefixed fields would place a region before offset 0.
    #[snafu(display("page table is inconsistent: data would start before offset 0"))]
    BadPageTable,
    /// A decompressed fsindex blob did not open with the expected magic.
    #[snafu(display("bad fsindex magic {magic:02x?}"))]
    BadMagic {
        /// The bytes actually found where the magic was expected.
        magic: Vec<u8>,
    },
    /// The fsindex parser did not consume exactly the bytes it was given.
    #[snafu(display("fsindex desynchronized: consumed {got} of {len} bytes"))]
    Desync {
        /// Bytes consumed by the parser.
        got: usize,
        /// Total length of the fsindex blob.
        len: usize,
    },
    /// A blob's leading id byte does not name any known codec.
    #[snafu(display("unknown compression id {id}"))]
    UnknownCodec {
        /// The unrecognised id byte.
        id: u8,
    },
    /// A blob's codec id is known but this build cannot decode it.
    #[snafu(display("codec {id} ({feature}) is not enabled in this build"))]
    CodecUnavailable {
        /// The wire id of the unavailable codec.
        id: u8,
        /// Human-readable name of the codec, for diagnostics.
        feature: &'static str,
    },
    /// A blob had no bytes at all, so no codec id could be read.
    #[snafu(display("blob is empty, missing codec id byte"))]
    EmptyBlob,
    /// A codec accepted the id byte but failed to decode the payload.
    #[snafu(display("decompression failed for {codec}"))]
    Decompress {
        /// Name of the codec that failed.
        codec: &'static str,
        /// Underlying decompression failure.
        source: std::io::Error,
    },
    /// A file block names a negative page, offset, or size.
    #[snafu(display("block references page {page} offset {offset} size {size}"))]
    BadBlock {
        /// Page index the block claims.
        page: i32,
        /// Byte offset within the page.
        offset: i32,
        /// Byte length within the page.
        size: i32,
    },
    /// A file block names a page index past the archive's page count.
    #[snafu(display("block references page {page} but archive holds only {pages} pages"))]
    PageOutOfRange {
        /// The requested page index.
        page: usize,
        /// The archive's actual page count.
        pages: usize,
    },
    /// A bounds-checked read ran past the end of its blob.
    ///
    /// Raised by the bounds-checked `Cursor` while walking a decompressed fsindex tree or
    /// CFS0003 pgindex table, so a truncated or crafted blob errors instead
    /// of panicking on an out-of-bounds slice.
    #[snafu(display("blob truncated: need {need} bytes at {pos}, has {len}"))]
    Truncated {
        /// Cursor position the read was attempted at.
        pos: usize,
        /// Bytes the read needed.
        need: usize,
        /// Total length of the blob being read.
        len: usize,
    },
}

/// The crate's result type, defaulting to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Reads exactly `len` bytes at `offset`.
///
/// # Errors
///
/// Returns [`Error::Io`] if the source does not have `len` bytes at `offset`.
pub fn at<R: ReadAt>(src: &R, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    src.read_exact_at(offset, &mut buf)
        .context(IoSnafu { offset })?;
    Ok(buf)
}

/// Reads a big-endian `u32` starting at `b[at]`.
///
/// Panics on out-of-bounds access. Callers must pre-validate that `b` holds at
/// least four bytes at `at`; use [`Cursor::be32`] for untrusted input.
pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap_or_else(|_| unreachable!()))
}

/// Scans backward from the end for any of `signatures`, confirmed by `validate`.
///
/// A hit is not necessarily the archive: an installer built around cookfs can
/// append other layers (a Metakit database, its own trailer, a code-signing
/// certificate) that happen to contain the same bytes. Every candidate is
/// confirmed by `validate`, which should attempt a full trailer parse for
/// whichever format `signatures[idx]` names.
///
/// All entries in `signatures` must share the same length; this holds for
/// every cookfs trailer signature to date (`CFS0002`, `CFS0003`, seven bytes
/// each).
///
/// # Errors
///
/// Returns [`Error::NoSignature`] if no candidate validates.
pub fn find_signature<R: ReadAt>(
    src: &R,
    len: u64,
    signatures: &[&[u8]],
    mut validate: impl FnMut(u64, usize) -> bool,
) -> Result<(u64, usize)> {
    const WINDOW: u64 = 1 << 20;

    let sig_len = signatures.first().map_or(0, |s| s.len());
    if sig_len == 0 {
        return NoSignatureSnafu.fail();
    }

    let mut end = len;
    while end > 0 {
        let start = end.saturating_sub(WINDOW);
        let span = at(src, start, (end - start) as usize + sig_len - 1)
            .or_else(|_| at(src, start, (end - start) as usize))?;

        for i in (0..span.len().saturating_sub(sig_len - 1)).rev() {
            for (idx, sig) in signatures.iter().enumerate() {
                if &span[i..i + sig_len] == *sig {
                    let candidate = start + i as u64;
                    if validate(candidate, idx) {
                        return Ok((candidate, idx));
                    }
                }
            }
        }
        end = start;
    }
    NoSignatureSnafu.fail()
}

/// A bounds-checked cursor over a byte slice.
///
/// Every blob this crate decodes after decompression, the fsindex tree and
/// the CFS0003 pgindex table, can be truncated by a corrupt or crafted
/// archive. A cursor turns an out-of-bounds read into [`Error::Truncated`]
/// instead of a panic.
pub struct Cursor<'a> {
    blob: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Starts a cursor at the front of `blob`.
    pub fn new(blob: &'a [u8]) -> Self {
        Self { blob, pos: 0 }
    }

    /// The cursor's current byte offset into the blob.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Takes and advances past the next `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if fewer than `len` bytes remain.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).context(TruncatedSnafu {
            pos: self.pos,
            need: len,
            len: self.blob.len(),
        })?;
        let slice = self.blob.get(self.pos..end).context(TruncatedSnafu {
            pos: self.pos,
            need: len,
            len: self.blob.len(),
        })?;
        self.pos = end;
        Ok(slice)
    }

    /// Takes and advances past one byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if no bytes remain.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Takes and advances past a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if fewer than 4 bytes remain.
    pub fn be32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().unwrap_or_else(|_| unreachable!()),
        ))
    }

    /// Takes and advances past a big-endian `i32`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if fewer than 4 bytes remain.
    pub fn be32i(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().unwrap_or_else(|_| unreachable!()),
        ))
    }

    /// Takes and advances past a big-endian `i64`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if fewer than 8 bytes remain.
    pub fn be64i(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().unwrap_or_else(|_| unreachable!()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn be32_round_trips_known_values() {
        for &v in &[0u32, 1, u32::MAX, 0x1234_5678] {
            check!(be32(&v.to_be_bytes(), 0) == v);
        }
    }

    #[test]
    fn be32_reads_at_a_nonzero_offset() {
        let mut buf = vec![0xAAu8; 3];
        buf.extend_from_slice(&42u32.to_be_bytes());
        check!(be32(&buf, 3) == 42);
    }

    #[test]
    fn at_reads_exact_bytes_at_offset() {
        let buf: &[u8] = b"hello world";
        check!(at(&buf, 6, 5).unwrap() == b"world");
    }

    #[test]
    fn at_errors_when_not_enough_bytes_remain() {
        let buf: &[u8] = b"short";
        check!(let Err(Error::Io { .. }) = at(&buf, 0, 100));
    }

    const SIG_A: &[u8] = b"AAAAAAA";
    const SIG_B: &[u8] = b"BBBBBBB";

    #[test]
    fn find_signature_returns_the_rightmost_candidate_that_validates() {
        let mut buf = vec![0xFFu8; 20];
        buf.extend_from_slice(SIG_A); // decoy: bytes match, validate rejects it
        buf.extend_from_slice(&[0xAAu8; 10]);
        let real_offset = buf.len() as u64;
        buf.extend_from_slice(SIG_B); // the real trailer

        let (found, which) = find_signature(
            &buf.as_slice(),
            buf.len() as u64,
            &[SIG_A, SIG_B],
            |_candidate, idx| idx == 1,
        )
        .unwrap();
        check!(found == real_offset);
        check!(which == 1);
    }

    #[test]
    fn find_signature_errors_when_no_bytes_match() {
        let buf = vec![0u8; 64];
        check!(let Err(Error::NoSignature) = find_signature(&buf.as_slice(), buf.len() as u64, &[SIG_A], |_, _| true));
    }

    #[test]
    fn find_signature_errors_when_nothing_validates() {
        let mut buf = vec![0u8; 20];
        buf.extend_from_slice(SIG_A);
        check!(let Err(Error::NoSignature) = find_signature(&buf.as_slice(), buf.len() as u64, &[SIG_A], |_, _| false));
    }

    #[test]
    fn cursor_reads_typed_values_in_sequence() {
        let mut blob = vec![7u8];
        blob.extend_from_slice(&42u32.to_be_bytes());
        blob.extend_from_slice(&(-1i32).to_be_bytes());
        blob.extend_from_slice(&(-2i64).to_be_bytes());
        blob.extend_from_slice(b"tail");

        let mut cursor = Cursor::new(&blob);
        check!(cursor.u8().unwrap() == 7);
        check!(cursor.be32().unwrap() == 42);
        check!(cursor.be32i().unwrap() == -1);
        check!(cursor.be64i().unwrap() == -2);
        check!(cursor.take(4).unwrap() == b"tail");
        check!(cursor.pos() == blob.len());
    }

    #[test]
    fn cursor_errors_instead_of_panicking_on_a_truncated_read() {
        let blob = vec![0u8; 2];
        let mut cursor = Cursor::new(&blob);
        check!(let Err(Error::Truncated { pos: 0, need: 4, len: 2 }) = cursor.be32());
    }
}
