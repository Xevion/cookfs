//! The `CFS0002` trailer, the format InstallBuilder ships.
//!
//! Every region is addressed by walking backward from the signature, each
//! offset the previous one less a length the trailer records:
//!
//! ```text
//! [pages][N x 16-byte hash slot][N x u32 compressed size][fsindex]
//! [u32 fsindex size][u32 N][u8 default compression]["CFS0002"]
//! ```
//!
//! Every blob names its own codec in its first byte; the default the head
//! records is informational.

use positioned_io::ReadAt;
use snafu::ResultExt;
use zerocopy::byteorder::big_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::{TrailerError, addressable, before, trailer_error};
use crate::page::{BlobRef, Codec, Layout};
use crate::source;
use crate::wire::Compression;

/// The seven bytes that end a `CFS0002` trailer.
pub(crate) const SIGNATURE: &[u8] = b"CFS0002";

/// The fixed fields between the fsindex and the signature.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Head {
    fsindex_len: U32,
    page_count: U32,
    default_compression: u8,
}

/// One page's 16-byte hash slot.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Slot([u8; 16]);

impl Slot {
    /// The uncompressed size, which only `crc32` hash mode records.
    ///
    /// That mode writes `[0, 0, size, crc32]`; the default `md5` mode writes a
    /// digest, which carries no size, and an all-zero slot is an unhashed page.
    fn declared_len(self) -> Option<u32> {
        let unhashed = self.0 == [0; 16];
        let crc_mode = self.0[..8] == [0; 8];
        (crc_mode && !unhashed)
            .then(|| u32::from_be_bytes([self.0[8], self.0[9], self.0[10], self.0[11]]))
    }
}

/// Bytes each page adds to the tables before the fsindex: a hash slot and a size.
const PER_PAGE: u64 = (size_of::<Slot>() + size_of::<U32>()) as u64;

/// Whether a signature at `sig_at` ends a trailer worth parsing, judged from a few bytes.
///
/// The scan asks this of every hit, so it reads only the head and the
/// fsindex's codec byte, and allocates nothing. A real archive always has an
/// fsindex, so an all-zero head (a stray signature after padding) is refused.
pub(crate) fn plausible<R: ReadAt>(src: &R, sig_at: u64) -> bool {
    let Some(head_at) = sig_at.checked_sub(size_of::<Head>() as u64) else {
        return false;
    };
    let Ok(head) = read::<Head, _>(src, head_at) else {
        return false;
    };
    let fsindex_len = u64::from(head.fsindex_len.get());
    let tables = u64::from(head.page_count.get()) * PER_PAGE;
    let Some(fsindex_at) = head_at.checked_sub(fsindex_len) else {
        return false;
    };
    let mut id = [0u8];
    fsindex_len > 0
        && tables <= fsindex_at
        && src.read_exact_at(fsindex_at, &mut id).is_ok()
        && LEGACY_CODECS.contains(&Compression::from_raw(id[0]))
}

/// The codecs a `CFS0002` blob can name; the legacy writer knows no others.
pub(crate) const LEGACY_CODECS: [Compression; 4] = [
    Compression::NONE,
    Compression::ZLIB,
    Compression::BZIP2,
    Compression::LEGACY_CUSTOM,
];

/// Parses the trailer behind a `CFS0002` signature at `sig_at`.
pub(crate) fn parse<R: ReadAt>(src: &R, sig_at: u64) -> Result<Layout, TrailerError> {
    let head_at = before("trailer head", sig_at, size_of::<Head>() as u64)?;
    let head = read::<Head, _>(src, head_at)?;
    let pages = u64::from(head.page_count.get());

    let fsindex_len = head.fsindex_len.get();
    snafu::ensure!(fsindex_len > 0, trailer_error::NoFsindex);
    let fsindex_at = before("fsindex", head_at, fsindex_len.into())?;
    let sizes_at = before("page size table", fsindex_at, pages * 4)?;
    let slots_at = before("page hash table", sizes_at, pages * 16)?;

    let sizes_raw = source::at(src, sizes_at, addressable("page size table", pages * 4)?)
        .context(trailer_error::Read)?;
    let sizes = <[U32]>::ref_from_bytes(&sizes_raw).unwrap_or(&[]);
    let slots_raw = source::at(src, slots_at, addressable("page hash table", pages * 16)?)
        .context(trailer_error::Read)?;
    let slots = <[Slot]>::ref_from_bytes(&slots_raw).unwrap_or(&[]);

    let total: u64 = sizes.iter().map(|s| u64::from(s.get())).sum();
    let mut at = before("page data", slots_at, total)?;

    let pages = sizes
        .iter()
        .zip(slots)
        .map(|(size, slot)| {
            let page = BlobRef {
                at,
                len: size.get(),
                codec: Codec::Prefixed,
                declared: slot.declared_len(),
                encrypted: false,
            };
            at += u64::from(size.get());
            page
        })
        .collect();

    Ok(Layout {
        pages,
        fsindex: BlobRef {
            at: fsindex_at,
            len: fsindex_len,
            codec: Codec::Prefixed,
            declared: None,
            encrypted: false,
        },
        encryption: None,
    })
}

fn read<T: FromBytes, R: ReadAt>(src: &R, at: u64) -> Result<T, TrailerError> {
    let raw = source::at(src, at, size_of::<T>()).context(trailer_error::Read)?;
    T::read_from_bytes(&raw).map_err(|_| TrailerError::Underflow {
        region: "trailer head",
        len: size_of::<T>() as u64,
        end: at,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert2::check;

    /// Builds a `CFS0002` archive from already-encoded page and fsindex blobs.
    pub(crate) fn archive(pages: &[(Vec<u8>, [u8; 16])], fsindex: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (blob, _) in pages {
            buf.extend_from_slice(blob);
        }
        for (_, slot) in pages {
            buf.extend_from_slice(slot);
        }
        for (blob, _) in pages {
            buf.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        }
        buf.extend_from_slice(fsindex);
        buf.extend_from_slice(&(fsindex.len() as u32).to_be_bytes());
        buf.extend_from_slice(&(pages.len() as u32).to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(SIGNATURE);
        buf
    }

    /// A `crc32`-mode slot recording `len`, with a zero checksum.
    pub(crate) fn crc_slot(len: u32) -> [u8; 16] {
        let mut slot = [0u8; 16];
        slot[8..12].copy_from_slice(&len.to_be_bytes());
        slot
    }

    fn sig_at(buf: &[u8]) -> u64 {
        (buf.len() - SIGNATURE.len()) as u64
    }

    #[test]
    fn pages_are_located_by_summing_sizes_backward_from_the_trailer() {
        let buf = archive(
            &[(vec![0; 10], crc_slot(100)), (vec![0; 20], crc_slot(200))],
            b"fsindex",
        );
        let layout = parse(&buf.as_slice(), sig_at(&buf)).unwrap();

        let got: Vec<_> = layout
            .pages
            .iter()
            .map(|p| (p.at, p.len, p.declared))
            .collect();
        check!(got == [(0, 10, Some(100)), (10, 20, Some(200))]);
        check!(let BlobRef { at: 70, len: 7, .. } = layout.fsindex);
    }

    #[test]
    fn only_a_crc32_slot_declares_a_size() {
        let mut md5 = [0xA5u8; 16];
        md5[8..12].copy_from_slice(&100u32.to_be_bytes());
        check!(Slot(md5).declared_len().is_none());
        check!(Slot([0; 16]).declared_len().is_none());
        check!(Slot(crc_slot(100)).declared_len() == Some(100));
    }

    #[test]
    fn an_empty_fsindex_is_refused() {
        let buf = archive(&[], b"");
        check!(let Err(TrailerError::NoFsindex) = parse(&buf.as_slice(), sig_at(&buf)));
    }

    #[test]
    fn plausibility_needs_an_fsindex_with_a_legacy_codec_that_fits() {
        let real = archive(&[(vec![0; 10], crc_slot(10))], &[1, 2, 3]);
        check!(plausible(&real.as_slice(), sig_at(&real)));

        let zeros = archive(&[], b"");
        check!(!plausible(&zeros.as_slice(), sig_at(&zeros)));

        let zstd_id = archive(&[], &[4, 0]);
        check!(!plausible(&zstd_id.as_slice(), sig_at(&zstd_id)));

        let mut huge = real;
        let count_at = huge.len() - SIGNATURE.len() - 5;
        huge[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        check!(!plausible(&huge.as_slice(), sig_at(&huge)));
    }

    #[test]
    fn a_page_count_larger_than_the_file_is_an_underflow() {
        let mut buf = archive(&[], &[0]);
        let count_at = buf.len() - SIGNATURE.len() - 5;
        buf[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        check!(let Err(TrailerError::Underflow { region: "page size table", .. }) = parse(&buf.as_slice(), sig_at(&buf)));
    }

    #[test]
    fn a_signature_too_near_the_start_is_an_underflow() {
        let buf = vec![0u8; 5];
        check!(let Err(TrailerError::Underflow { region: "trailer head", .. }) = parse(&buf.as_slice(), 5));
    }
}
