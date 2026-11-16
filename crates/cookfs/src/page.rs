//! The page table every format-specific parser normalizes into.
//!
//! `CFS0002` names a blob's codec in the blob's own first byte, `CFS0003` in a
//! separate table. Past [`crate::Archive::open`] nothing asks which format it
//! opened: every read goes through a [`BlobRef`].

use crate::codec::{self, CodecError, Expect};
use crate::wire::Compression;

/// How a blob names its codec.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Codec {
    /// The blob's first byte names it (`CFS0002`).
    Prefixed,
    /// A table outside the blob names it, and the blob carries no id byte (`CFS0003`).
    External(Compression),
}

/// Where one compressed blob lives and what it should decode to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlobRef {
    /// Offset of the compressed bytes in the source.
    pub(crate) at: u64,
    /// Compressed length.
    pub(crate) len: u32,
    /// How the blob names its codec.
    pub(crate) codec: Codec,
    /// Decoded length, when the archive records one.
    pub(crate) declared: Option<u32>,
    /// Whether the pgindex flags the page as encrypted.
    pub(crate) encrypted: bool,
}

impl BlobRef {
    pub(crate) fn decode(&self, raw: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
        let expect = Expect {
            declared: self.declared.map(|n| n as usize),
            limit,
        };
        match self.codec {
            Codec::Prefixed => codec::decode_prefixed(raw, expect),
            Codec::External(id) => codec::decode_external(id, raw, expect),
        }
    }
}

/// Everything [`crate::Archive::open`] needs once a format parser has run.
#[derive(Debug)]
pub(crate) struct Layout {
    /// Every data page, in page-index order.
    pub(crate) pages: Vec<BlobRef>,
    /// The fsindex blob.
    pub(crate) fsindex: BlobRef,
    /// The `CFS0003` encryption byte; `CFS0002` has none.
    pub(crate) encryption: Option<crate::Encryption>,
}
