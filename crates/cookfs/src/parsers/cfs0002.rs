//! `CFS0002` trailer and page-table parsing.
//!
//! Everything a `CFS0002` archive needs to describe itself lives in a
//! fixed-shape trailer appended after the signature: a 9-byte head, a
//! page-size table, and a 16-byte-per-page meta table, each addressed by
//! walking outward from the signature using the previous field's length.

use positioned_io::ReadAt;
use snafu::OptionExt;

use crate::page::{Layout, PageCodec, PageEntry, PageTable};
use crate::read::{BadPageTableSnafu, Result, at, be32};

/// The seven bytes that mark the end of a `CFS0002` trailer.
pub const SIGNATURE: &[u8] = b"CFS0002";

/// Parses the trailer and page table behind a `CFS0002` signature at `sig_at`.
///
/// # Errors
///
/// Returns [`crate::Error::BadPageTable`] if any length-prefixed field would
/// place a region before offset 0, or [`crate::Error::Io`] if a read runs
/// past the source's bounds.
pub fn parse<R: ReadAt>(src: &R, sig_at: u64) -> Result<Layout> {
    let head_at = sig_at.checked_sub(9).context(BadPageTableSnafu)?;
    let head = at(src, head_at, 9)?;
    let fsindex_len = be32(&head, 0) as usize;
    let page_count = be32(&head, 4) as usize;
    // head[8] is the archive-wide codec id; every blob names its own id, so
    // it carries no information this reader needs.

    let fsindex_at = head_at
        .checked_sub(fsindex_len as u64)
        .context(BadPageTableSnafu)?;
    let sizes_at = fsindex_at
        .checked_sub(4 * page_count as u64)
        .context(BadPageTableSnafu)?;
    // 16 bytes per page. Upstream calls this an MD5 digest; with
    // `cookfs.pagehash: crc32` the last 8 bytes read as size + CRC-32.
    let meta_at = sizes_at
        .checked_sub(16 * page_count as u64)
        .context(BadPageTableSnafu)?;

    let raw = at(src, sizes_at, 4 * page_count)?;
    let page_sizes: Vec<u32> = (0..page_count).map(|i| be32(&raw, i * 4)).collect();

    let total: u64 = page_sizes.iter().map(|&s| u64::from(s)).sum();
    let pages_at = meta_at.checked_sub(total).context(BadPageTableSnafu)?;

    let meta = at(src, meta_at, 16 * page_count)?;
    let page_uncompressed: Vec<u32> = (0..page_count).map(|i| be32(&meta, i * 16 + 8)).collect();

    let mut offset = pages_at;
    let mut entries = Vec::with_capacity(page_count);
    for i in 0..page_count {
        entries.push(PageEntry {
            offset,
            compressed_len: page_sizes[i],
            uncompressed_len: page_uncompressed[i],
            codec: PageCodec::Prefixed,
        });
        offset += u64::from(page_sizes[i]);
    }

    Ok(Layout {
        pages: PageTable { entries },
        fsindex_at,
        fsindex_len,
        fsindex_uncompressed_len: None,
        fsindex_codec: PageCodec::Prefixed,
        encryption: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    /// Builds a minimal trailer with zero pages: fsindex blob, then the
    /// 9-byte head, then the signature.
    fn minimal_trailer_buffer(fsindex: &[u8], codec: u8) -> (Vec<u8>, u64) {
        let mut buf = fsindex.to_vec();
        buf.extend_from_slice(&(fsindex.len() as u32).to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.push(codec);
        let sig_at = buf.len() as u64;
        buf.extend_from_slice(SIGNATURE);
        (buf, sig_at)
    }

    #[test]
    fn parse_reads_an_empty_archive_with_zero_pages() {
        let (buf, sig_at) = minimal_trailer_buffer(b"fake-fsindex", 3);
        let layout = parse(&buf.as_slice(), sig_at).unwrap();

        check!(layout.fsindex_at == 0);
        check!(layout.fsindex_len == 12);
        check!(layout.pages.entries.is_empty());
        check!(layout.encryption.is_none());
    }

    #[test]
    fn parse_reads_pages_with_offsets_and_sizes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 10]); // page 0 compressed data
        buf.extend_from_slice(&[0u8; 20]); // page 1 compressed data

        let mut meta0 = vec![0u8; 16];
        meta0[8..12].copy_from_slice(&100u32.to_be_bytes());
        let mut meta1 = vec![0u8; 16];
        meta1[8..12].copy_from_slice(&200u32.to_be_bytes());
        buf.extend_from_slice(&meta0);
        buf.extend_from_slice(&meta1);

        buf.extend_from_slice(&10u32.to_be_bytes());
        buf.extend_from_slice(&20u32.to_be_bytes());

        let fsindex = b"fake-fsindex-blob";
        buf.extend_from_slice(fsindex);

        buf.extend_from_slice(&(fsindex.len() as u32).to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.push(7);

        let sig_at = buf.len() as u64;
        buf.extend_from_slice(SIGNATURE);

        let layout = parse(&buf.as_slice(), sig_at).unwrap();
        check!(layout.pages.entries.len() == 2);
        check!(layout.pages.entries[0].offset == 0);
        check!(layout.pages.entries[0].compressed_len == 10);
        check!(layout.pages.entries[0].uncompressed_len == 100);
        check!(layout.pages.entries[1].offset == 10);
        check!(layout.pages.entries[1].compressed_len == 20);
        check!(layout.pages.entries[1].uncompressed_len == 200);
        check!(matches!(layout.pages.entries[0].codec, PageCodec::Prefixed));
    }

    #[test]
    fn parse_rejects_a_page_table_that_underflows() {
        // page_count claims more pages than the buffer could ever hold.
        let mut buf = vec![0u8; 9];
        buf[0..4].copy_from_slice(&0u32.to_be_bytes());
        buf[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        let sig_at = 9u64;
        let mut full = buf;
        full.extend_from_slice(SIGNATURE);
        check!(let Err(crate::Error::BadPageTable) = parse(&full.as_slice(), sig_at));
    }

    #[test]
    fn parse_rejects_a_signature_too_close_to_the_start() {
        let buf = vec![0u8; 5];
        check!(let Err(crate::Error::BadPageTable) = parse(&buf.as_slice(), 5));
    }
}
