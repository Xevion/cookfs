//! The normalized page table shared by every format-specific parser.
//!
//! `CFS0002` and `CFS0003` name a page's codec differently: a blob's own
//! leading byte, or an id carried out of band in a separate table. Everything
//! past `Archive::open` reads through [`PageEntry::codec`] instead of asking
//! which format it opened, so the version branch fires once, at parse time.

use crate::codec::Codec;

/// How to decode one blob: a page, or the fsindex itself.
#[derive(Debug, Clone, Copy)]
pub enum PageCodec {
    /// The blob's own leading byte names its codec (`CFS0002`).
    Prefixed,
    /// The codec is already known; the blob carries no leading byte (`CFS0003`).
    External(Codec),
}

/// One page's location, size, and how to decode it.
#[derive(Debug, Clone, Copy)]
pub struct PageEntry {
    /// Byte offset of the page's compressed data in the source.
    pub offset: u64,
    /// Compressed length in bytes.
    pub compressed_len: u32,
    /// Decompressed length in bytes.
    pub uncompressed_len: u32,
    /// How to decode this page's blob.
    pub codec: PageCodec,
}

/// Every page an archive holds, in page-index order.
#[derive(Debug, Default)]
pub struct PageTable {
    /// One entry per page, indexed by page number.
    pub entries: Vec<PageEntry>,
}

/// Everything `Archive::open` needs once a format-specific parser has run.
///
/// Producing this is the one place a version branch fires: every parser in
/// `parsers` builds one of these from its own trailer shape, and every read
/// path afterward is version-blind.
#[derive(Debug)]
pub struct Layout {
    /// The page table.
    pub pages: PageTable,
    /// Byte offset of the compressed fsindex blob.
    pub fsindex_at: u64,
    /// Compressed length of the fsindex blob.
    pub fsindex_len: usize,
    /// Decompressed length of the fsindex blob, if the format declares one.
    ///
    /// `CFS0003` always knows this; `CFS0002`'s trailer has no such field.
    /// Only [`Codec::Lzma`] needs it, to bound a raw LZMA1 stream that has no
    /// end-of-stream marker of its own.
    pub fsindex_uncompressed_len: Option<u32>,
    /// How to decode the fsindex blob.
    pub fsindex_codec: PageCodec,
    /// `CFS0003`'s encryption byte; `None` for `CFS0002`, which has none.
    pub encryption: Option<u8>,
}
