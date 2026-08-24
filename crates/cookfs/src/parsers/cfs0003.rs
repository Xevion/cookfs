//! `CFS0003` trailer, pgindex, and page-table parsing.
//!
//! `CFS0003` moves per-page compression out of each page blob and into a
//! separate pgindex table, itself a compressed blob whose own compression id
//! and size live in the trailer. The trailer is fixed-size (55 bytes, plus
//! the 7-byte signature): unlike `CFS0002`, nothing about its own shape
//! depends on the page count.
//!
//! Byte layout verified against upstream Tcl:
//! <https://github.com/chpock/cookfs/blob/main/scripts/pages.tcl#L366-L443>

use positioned_io::ReadAt;
use snafu::OptionExt;

use crate::codec::{self, Codec};
use crate::page::{Layout, PageCodec, PageEntry, PageTable};
use crate::read::{BadPageTableSnafu, Cursor, Result, at};

/// The seven bytes that mark the end of a `CFS0003` trailer.
pub const SIGNATURE: &[u8] = b"CFS0003";

/// Bytes of fixed trailer fields preceding the signature (55 + 7 = 62 total).
const TRAILER_LEN: u64 = 55;

/// The fixed fields behind a `CFS0003` signature, before the pgindex and
/// fsindex blobs are read.
#[derive(Debug)]
pub struct Trailer {
    /// Archive-wide compression id. Not currently used; every page and the
    /// fsindex name their own codec.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "parsed for completeness; every blob names its own codec id"
        )
    )]
    pub base_compression: u8,
    /// Archive-wide compression level.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "parsed for completeness and round-trip tested; not needed to build a Layout"
        )
    )]
    pub base_compression_level: u8,
    /// Semantics unconfirmed upstream; both known samples read `0x78` and
    /// upstream Tcl does not gate behavior on this value.
    pub encryption: u8,
    /// Compression id of the pgindex blob.
    pub pgindex_compression: u8,
    /// Compression level of the pgindex blob.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "parsed for completeness and round-trip tested; not needed to build a Layout"
        )
    )]
    pub pgindex_compression_level: u8,
    /// MD5 digest of the decompressed pgindex blob.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "parsed for completeness and round-trip tested; not needed to build a Layout"
        )
    )]
    pub pgindex_md5: [u8; 16],
    /// Compressed length of the pgindex blob.
    pub pgindex_size_compressed: u32,
    /// Decompressed length of the pgindex blob.
    pub pgindex_size_uncompressed: u32,
    /// Compression id of the fsindex blob.
    pub fsindex_compression: u8,
    /// Compression level of the fsindex blob.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "parsed for completeness and round-trip tested; not needed to build a Layout"
        )
    )]
    pub fsindex_compression_level: u8,
    /// MD5 digest of the decompressed fsindex blob.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "parsed for completeness and round-trip tested; not needed to build a Layout"
        )
    )]
    pub fsindex_md5: [u8; 16],
    /// Compressed length of the fsindex blob.
    pub fsindex_size_compressed: u32,
    /// Decompressed length of the fsindex blob.
    pub fsindex_size_uncompressed: u32,
}

impl Trailer {
    /// Parses the fixed trailer fields behind a `CFS0003` signature at `sig_at`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::BadPageTable`] if `sig_at` is too close to the
    /// start of the source to hold a full trailer, or [`crate::Error::Io`] if
    /// a read runs past the source's bounds.
    pub fn parse<R: ReadAt>(src: &R, sig_at: u64) -> Result<Self> {
        let trailer_at = sig_at.checked_sub(TRAILER_LEN).context(BadPageTableSnafu)?;
        let buf = at(src, trailer_at, TRAILER_LEN as usize)?;
        let mut c = Cursor::new(&buf);

        Ok(Self {
            base_compression: c.u8()?,
            base_compression_level: c.u8()?,
            encryption: c.u8()?,
            pgindex_compression: c.u8()?,
            pgindex_compression_level: c.u8()?,
            pgindex_md5: c.take(16)?.try_into().unwrap_or_else(|_| unreachable!()),
            pgindex_size_compressed: c.be32()?,
            pgindex_size_uncompressed: c.be32()?,
            fsindex_compression: c.u8()?,
            fsindex_compression_level: c.u8()?,
            fsindex_md5: c.take(16)?.try_into().unwrap_or_else(|_| unreachable!()),
            fsindex_size_compressed: c.be32()?,
            fsindex_size_uncompressed: c.be32()?,
        })
    }
}

/// Per-page codec ids and sizes decoded from a `CFS0003` pgindex blob.
#[derive(Debug)]
pub struct PgIndex {
    /// Per-page compression id, in page order.
    pub compr: Vec<u8>,
    /// Per-page compressed length, in page order.
    pub size_compressed: Vec<u32>,
    /// Per-page decompressed length, in page order.
    pub size_uncompressed: Vec<u32>,
}

impl PgIndex {
    /// Parses a decompressed pgindex blob's page arrays.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Truncated`] if the blob is shorter than its
    /// own declared page count requires.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(blob);
        let page_count = c.be32()? as usize;

        let compr = c.take(page_count)?.to_vec();
        c.take(page_count)?; // per-page compression level, unused
        c.take(page_count)?; // per-page encryption flag, unused

        let mut size_compressed = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            size_compressed.push(c.be32()?);
        }
        let mut size_uncompressed = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            size_uncompressed.push(c.be32()?);
        }
        c.take(page_count * 16)?; // per-page md5, unused

        Ok(Self {
            compr,
            size_compressed,
            size_uncompressed,
        })
    }
}

/// Parses the trailer, pgindex, and page table behind a `CFS0003` signature.
///
/// Unlike [`Trailer::parse`], this decompresses the pgindex blob, so it
/// should only run once a candidate signature is already confirmed.
///
/// # Errors
///
/// Returns [`crate::Error::BadPageTable`] if any length-prefixed field would
/// place a region before offset 0, [`crate::Error::UnknownCodec`] if a page
/// or the pgindex itself names an unrecognised codec id, and any error the
/// pgindex codec's decoder can produce.
pub fn parse<R: ReadAt>(src: &R, sig_at: u64) -> Result<Layout> {
    let trailer = Trailer::parse(src, sig_at)?;
    let trailer_at = sig_at.checked_sub(TRAILER_LEN).context(BadPageTableSnafu)?;

    let fsindex_at = trailer_at
        .checked_sub(u64::from(trailer.fsindex_size_compressed))
        .context(BadPageTableSnafu)?;
    let pgindex_at = fsindex_at
        .checked_sub(u64::from(trailer.pgindex_size_compressed))
        .context(BadPageTableSnafu)?;

    let pgindex_raw = at(src, pgindex_at, trailer.pgindex_size_compressed as usize)?;
    let pgindex_codec = Codec::from_id(trailer.pgindex_compression)?;
    let pgindex_plain = codec::decode_with(
        pgindex_codec,
        &pgindex_raw,
        trailer.pgindex_size_uncompressed as usize,
    )?;
    let pgindex = PgIndex::parse(&pgindex_plain)?;

    let total_compressed: u64 = pgindex.size_compressed.iter().map(|&s| u64::from(s)).sum();
    let pages_at = pgindex_at
        .checked_sub(total_compressed)
        .context(BadPageTableSnafu)?;

    let mut offset = pages_at;
    let mut entries = Vec::with_capacity(pgindex.compr.len());
    for i in 0..pgindex.compr.len() {
        entries.push(PageEntry {
            offset,
            compressed_len: pgindex.size_compressed[i],
            uncompressed_len: pgindex.size_uncompressed[i],
            codec: PageCodec::External(Codec::from_id(pgindex.compr[i])?),
        });
        offset += u64::from(pgindex.size_compressed[i]);
    }

    let fsindex_codec = Codec::from_id(trailer.fsindex_compression)?;

    Ok(Layout {
        pages: PageTable { entries },
        fsindex_at,
        fsindex_len: trailer.fsindex_size_compressed as usize,
        fsindex_uncompressed_len: Some(trailer.fsindex_size_uncompressed),
        fsindex_codec: PageCodec::External(fsindex_codec),
        encryption: Some(trailer.encryption),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    /// One trailer blob descriptor: compression id, MD5, and both sizes.
    #[derive(Clone, Copy)]
    struct BlobDescriptor {
        compression: u8,
        md5: [u8; 16],
        size_compressed: u32,
        size_uncompressed: u32,
    }

    impl BlobDescriptor {
        fn zero() -> Self {
            Self {
                compression: 0,
                md5: [0u8; 16],
                size_compressed: 0,
                size_uncompressed: 0,
            }
        }
    }

    /// Appends the 55 fixed trailer bytes for the given field values.
    fn push_trailer(
        buf: &mut Vec<u8>,
        pgindex: BlobDescriptor,
        fsindex: BlobDescriptor,
        encryption: u8,
    ) {
        buf.push(1); // base_compression
        buf.push(6); // base_compression_level
        buf.push(encryption);
        buf.push(pgindex.compression);
        buf.push(9); // pgindex_compression_level
        buf.extend_from_slice(&pgindex.md5);
        buf.extend_from_slice(&pgindex.size_compressed.to_be_bytes());
        buf.extend_from_slice(&pgindex.size_uncompressed.to_be_bytes());
        buf.push(fsindex.compression);
        buf.push(9); // fsindex_compression_level
        buf.extend_from_slice(&fsindex.md5);
        buf.extend_from_slice(&fsindex.size_compressed.to_be_bytes());
        buf.extend_from_slice(&fsindex.size_uncompressed.to_be_bytes());
    }

    #[test]
    fn trailer_parses_an_empty_archive_with_zero_pages() {
        let mut buf = Vec::new();
        push_trailer(&mut buf, BlobDescriptor::zero(), BlobDescriptor::zero(), 0);
        let sig_at = buf.len() as u64;
        buf.extend_from_slice(SIGNATURE);

        let trailer = Trailer::parse(&buf.as_slice(), sig_at).unwrap();
        check!(trailer.pgindex_size_compressed == 0);
        check!(trailer.fsindex_size_compressed == 0);
        check!(trailer.encryption == 0);
    }

    #[test]
    fn trailer_round_trips_pgindex_and_fsindex_descriptors() {
        let pgindex_md5 = [0xAAu8; 16];
        let fsindex_md5 = [0xBBu8; 16];
        let pgindex = BlobDescriptor {
            compression: 2,
            md5: pgindex_md5,
            size_compressed: 58,
            size_uncompressed: 100,
        };
        let fsindex = BlobDescriptor {
            compression: 3,
            md5: fsindex_md5,
            size_compressed: 200,
            size_uncompressed: 500,
        };
        let mut buf = Vec::new();
        push_trailer(&mut buf, pgindex, fsindex, 0x78);
        let sig_at = buf.len() as u64;
        buf.extend_from_slice(SIGNATURE);

        let trailer = Trailer::parse(&buf.as_slice(), sig_at).unwrap();
        check!(trailer.base_compression == 1);
        check!(trailer.base_compression_level == 6);
        check!(trailer.encryption == 0x78);
        check!(trailer.pgindex_compression == 2);
        check!(trailer.pgindex_compression_level == 9);
        check!(trailer.pgindex_md5 == pgindex_md5);
        check!(trailer.pgindex_size_compressed == 58);
        check!(trailer.pgindex_size_uncompressed == 100);
        check!(trailer.fsindex_compression == 3);
        check!(trailer.fsindex_compression_level == 9);
        check!(trailer.fsindex_md5 == fsindex_md5);
        check!(trailer.fsindex_size_compressed == 200);
        check!(trailer.fsindex_size_uncompressed == 500);
    }

    #[test]
    fn trailer_rejects_a_signature_too_close_to_the_start() {
        let buf = vec![0u8; 10];
        check!(let Err(crate::Error::BadPageTable) = Trailer::parse(&buf.as_slice(), 10));
    }

    fn pgindex_blob(compr: &[u8], size_compressed: &[u32], size_uncompressed: &[u32]) -> Vec<u8> {
        let n = compr.len();
        let mut blob = (n as u32).to_be_bytes().to_vec();
        blob.extend_from_slice(compr);
        blob.extend_from_slice(&vec![6u8; n]); // comprlevellist
        blob.extend_from_slice(&vec![0u8; n]); // encryptionlist
        for &s in size_compressed {
            blob.extend_from_slice(&s.to_be_bytes());
        }
        for &s in size_uncompressed {
            blob.extend_from_slice(&s.to_be_bytes());
        }
        blob.extend_from_slice(&vec![0u8; n * 16]); // md5
        blob
    }

    #[test]
    fn pgindex_parses_comprlist_and_sizes_for_two_pages() {
        let blob = pgindex_blob(&[3, 0], &[100, 200], &[50, 150]);
        let idx = PgIndex::parse(&blob).unwrap();
        check!(idx.compr == vec![3, 0]);
        check!(idx.size_compressed == vec![100, 200]);
        check!(idx.size_uncompressed == vec![50, 150]);
    }

    #[test]
    fn pgindex_parses_zero_pages() {
        let blob = pgindex_blob(&[], &[], &[]);
        let idx = PgIndex::parse(&blob).unwrap();
        check!(idx.compr.is_empty());
    }

    #[test]
    fn pgindex_errors_instead_of_panicking_on_truncation() {
        let mut blob = pgindex_blob(&[3, 0], &[100, 200], &[50, 150]);
        blob.truncate(blob.len() - 5);
        check!(let Err(crate::Error::Truncated { .. }) = PgIndex::parse(&blob));
    }
}
