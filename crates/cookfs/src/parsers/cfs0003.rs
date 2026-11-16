//! The `CFS0003` trailer, the format upstream cookfs writes since 2024.
//!
//! Per-page codecs and sizes move out of the blobs into a pgindex, itself a
//! compressed blob that the fixed-size suffix describes:
//!
//! ```text
//! [pages][pgindex][fsindex][55-byte suffix]["CFS0003"][encryption data]
//! ```
//!
//! The encryption data after the signature is absent unless the archive is
//! encrypted. Layout verified against upstream `generic/pages.c`.

use positioned_io::ReadAt;
use snafu::ResultExt;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::{TrailerError, before, trailer_error};
use crate::Limits;
use crate::bytes::Reader;
use crate::page::{BlobRef, Codec, Layout};
use crate::source;
use crate::wire::Compression;

/// The seven bytes that end a `CFS0003` suffix.
pub(crate) const SIGNATURE: &[u8] = b"CFS0003";

/// Compression, level, hash and sizes of the pgindex or fsindex blob.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct BlobInfo {
    compression: u8,
    level: u8,
    md5: [u8; 16],
    size_compressed: U32,
    size_uncompressed: U32,
}

/// The fixed fields before the signature.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct Suffix {
    base_compression: u8,
    base_level: u8,
    encryption: u8,
    pgindex: BlobInfo,
    fsindex: BlobInfo,
}

#[expect(
    unreachable_pub,
    reason = "bitbybit makes the accessors it generates `pub`"
)]
mod encryption_byte {
    use arbitrary_int::{u3, u5};
    use bitbybit::bitfield;

    /// The suffix's encryption byte: a mode in the low three bits, the key-derivation level above.
    #[bitfield(u8)]
    pub(super) struct EncryptionByte {
        #[bits(3..=7, r)]
        level: u5,
        #[bits(0..=2, r)]
        mode: u3,
    }
}

use encryption_byte::EncryptionByte;

crate::wire::wire_enum! {
    /// How a `CFS0003` archive is encrypted.
    pub struct EncryptionMode(u8) {
        /// Not encrypted.
        NONE = 0,
        /// Pages encrypted with a key derived from the password.
        FILE = 1,
        /// Pages encrypted with a random key, itself encrypted by the password.
        KEY = 2,
        /// As [`Self::KEY`], with the pgindex and fsindex encrypted too.
        KEY_INDEX = 3,
    }
}

/// A `CFS0003` archive's encryption mode and key-derivation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encryption {
    /// The mode.
    pub mode: EncryptionMode,
    /// The PBKDF2 level, 0 to 31; upstream's default is 15.
    pub level: u8,
}

impl From<u8> for Encryption {
    fn from(raw: u8) -> Self {
        let byte = EncryptionByte::new_with_raw_value(raw);
        Self {
            mode: EncryptionMode::from_raw(byte.mode().value()),
            level: byte.level().value(),
        }
    }
}

const SUFFIX_LEN: u64 = size_of::<Suffix>() as u64;

/// The smallest pgindex record: id, level and encryption bytes, two sizes, and a hash.
const PGINDEX_RECORD_LEN: usize = 1 + 1 + 1 + 4 + 4 + 16;

impl Suffix {
    /// Reads the fixed suffix behind a `CFS0003` signature at `sig_at`.
    pub(crate) fn read<R: ReadAt>(src: &R, sig_at: u64) -> Result<Self, TrailerError> {
        let at = before("trailer suffix", sig_at, SUFFIX_LEN)?;
        let raw = source::at(src, at, SUFFIX_LEN as usize).context(trailer_error::Read)?;
        Self::read_from_bytes(&raw).map_err(|_| TrailerError::Underflow {
            region: "trailer suffix",
            len: SUFFIX_LEN,
            end: sig_at,
        })
    }

    /// Whether the pgindex and fsindex this suffix describes fit before it, as upstream checks before trusting it.
    pub(crate) fn fits_before(&self, sig_at: u64) -> bool {
        let indexes = u64::from(self.pgindex.size_compressed.get())
            + u64::from(self.fsindex.size_compressed.get());
        indexes + SUFFIX_LEN <= sig_at
    }
}

/// Parses the suffix, pgindex and page table behind a `CFS0003` signature.
pub(crate) fn parse<R: ReadAt>(
    src: &R,
    sig_at: u64,
    limits: &Limits,
) -> Result<Layout, TrailerError> {
    let suffix = Suffix::read(src, sig_at)?;
    let suffix_at = sig_at - SUFFIX_LEN;

    let fsindex_len = suffix.fsindex.size_compressed.get();
    let fsindex_at = before("fsindex", suffix_at, fsindex_len.into())?;
    let pgindex_len = suffix.pgindex.size_compressed.get();
    let pgindex_at = before("pgindex", fsindex_at, pgindex_len.into())?;

    let pages = if pgindex_len == 0 {
        Vec::new()
    } else {
        let pgindex = blob(pgindex_at, suffix.pgindex);
        let raw = source::at(src, pgindex_at, pgindex_len as usize).context(trailer_error::Read)?;
        let plain = pgindex
            .decode(&raw, limits.max_page_len)
            .context(trailer_error::PgindexBlob)?;
        page_table(&plain, pgindex_at)?
    };

    Ok(Layout {
        pages,
        fsindex: (fsindex_len > 0).then(|| blob(fsindex_at, suffix.fsindex)),
        encryption: Some(Encryption::from(suffix.encryption)),
    })
}

const fn blob(at: u64, info: BlobInfo) -> BlobRef {
    BlobRef {
        at,
        len: info.size_compressed.get(),
        codec: Codec::External(Compression::from_raw(info.compression)),
        declared: Some(info.size_uncompressed.get()),
    }
}

/// Decodes the pgindex's struct-of-arrays into pages ending at `end`.
///
/// ```text
/// u32 N, N x u8 compression, N x u8 level, N x u8 encrypted,
/// N x u32 compressed size, N x u32 uncompressed size, N x 16-byte MD5
/// ```
fn page_table(plain: &[u8], end: u64) -> Result<Vec<BlobRef>, TrailerError> {
    let mut r = Reader::new(plain);
    let count = r
        .record::<U32>()
        .context(trailer_error::PgindexLayout)?
        .get();
    let n = r
        .check_count(count, PGINDEX_RECORD_LEN)
        .context(trailer_error::PgindexLayout)?;

    let compression = r.take(n).context(trailer_error::PgindexLayout)?;
    r.take(n).context(trailer_error::PgindexLayout)?; // levels
    r.take(n).context(trailer_error::PgindexLayout)?; // encryption flags
    let compressed = r
        .records::<U32>(count)
        .context(trailer_error::PgindexLayout)?;
    let uncompressed = r
        .records::<U32>(count)
        .context(trailer_error::PgindexLayout)?;
    r.records::<[u8; 16]>(count)
        .context(trailer_error::PgindexLayout)?;

    let total: u64 = compressed.iter().map(|s| u64::from(s.get())).sum();
    let mut at = before("page data", end, total)?;

    Ok(compression
        .iter()
        .zip(compressed)
        .zip(uncompressed)
        .map(|((&id, len), declared)| {
            let page = BlobRef {
                at,
                len: len.get(),
                codec: Codec::External(Compression::from_raw(id)),
                declared: Some(declared.get()),
            };
            at += u64::from(len.get());
            page
        })
        .collect())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert2::check;

    /// A stored pgindex blob describing `pages` as `(compressed, uncompressed)` sizes.
    pub(crate) fn pgindex(pages: &[(u32, u32)]) -> Vec<u8> {
        let n = pages.len();
        let mut blob = (n as u32).to_be_bytes().to_vec();
        blob.extend(std::iter::repeat_n(0u8, 3 * n)); // stored, level 0, not encrypted
        for &(c, _) in pages {
            blob.extend_from_slice(&c.to_be_bytes());
        }
        for &(_, u) in pages {
            blob.extend_from_slice(&u.to_be_bytes());
        }
        blob.extend(std::iter::repeat_n(0u8, 16 * n));
        blob
    }

    /// Builds a `CFS0003` archive with stored pages and a stored fsindex.
    pub(crate) fn archive(pages: &[Vec<u8>], fsindex: &[u8], encryption: u8) -> Vec<u8> {
        let sizes: Vec<_> = pages
            .iter()
            .map(|p| (p.len() as u32, p.len() as u32))
            .collect();
        let pgindex = pgindex(&sizes);

        let mut buf: Vec<u8> = pages.concat();
        buf.extend_from_slice(&pgindex);
        buf.extend_from_slice(fsindex);
        buf.extend_from_slice(&[0, 0, encryption]);
        for len in [pgindex.len(), fsindex.len()] {
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&[0; 16]);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
        buf.extend_from_slice(SIGNATURE);
        buf
    }

    fn sig_at(buf: &[u8]) -> u64 {
        (buf.len() - SIGNATURE.len()) as u64
    }

    #[test]
    fn the_suffix_is_fifty_five_bytes() {
        check!(SUFFIX_LEN == 55);
    }

    #[test]
    fn pages_are_located_before_the_pgindex() {
        let buf = archive(&[vec![1; 10], vec![2; 20]], b"fsindex", 0);
        let layout = parse(&buf.as_slice(), sig_at(&buf), &Limits::default()).unwrap();
        let got: Vec<_> = layout.pages.iter().map(|p| (p.at, p.len)).collect();
        check!(got == [(0, 10), (10, 20)]);
    }

    #[test]
    fn the_encryption_byte_splits_into_mode_and_level() {
        check!(
            Encryption::from(0x78)
                == Encryption {
                    mode: EncryptionMode::NONE,
                    level: 15
                }
        );
        check!(
            Encryption::from(0x7B)
                == Encryption {
                    mode: EncryptionMode::KEY_INDEX,
                    level: 15
                }
        );
    }

    #[test]
    fn an_empty_pgindex_and_fsindex_describe_an_empty_archive() {
        let mut buf = vec![0u8; 55];
        buf.extend_from_slice(SIGNATURE);
        let layout = parse(&buf.as_slice(), 55, &Limits::default()).unwrap();
        check!(layout.pages.is_empty());
        check!(layout.fsindex.is_none());
    }

    #[test]
    fn a_pgindex_count_larger_than_its_blob_is_refused() {
        let blob = u32::MAX.to_be_bytes();
        check!(let Err(TrailerError::PgindexLayout { .. }) = page_table(&blob, 1 << 40));
    }

    #[test]
    fn a_suffix_too_near_the_start_is_an_underflow() {
        let buf = vec![0u8; 10];
        check!(let Err(TrailerError::Underflow { region: "trailer suffix", .. }) = Suffix::read(&buf.as_slice(), 10));
    }
}
