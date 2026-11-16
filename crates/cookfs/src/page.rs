//! The page table every format-specific parser normalizes into.
//!
//! `CFS0002` names a blob's codec in the blob's own first byte, `CFS0003` in a
//! separate table. Past [`crate::Archive::open`] nothing asks which format it
//! opened: every read goes through a [`BlobRef`].

use md5::{Digest, Md5};

use crate::codec::{self, CodecError, Expect, codec_error};
use crate::wire::Compression;

/// What a blob's stored 16-byte hash says its decoded bytes are.
///
/// Both formats store the same shapes: all zero for a blob written unhashed,
/// `[0, 0, size, crc32]` big-endian in `crc32` mode, and otherwise an MD5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hash {
    /// Written without a hash, so nothing can be checked.
    Unhashed,
    /// The MD5 of the decoded bytes.
    Md5([u8; 16]),
    /// The CRC-32 of the decoded bytes.
    Crc32(u32),
}

impl Hash {
    pub(crate) fn from_slot(slot: [u8; 16]) -> Self {
        if slot == [0; 16] {
            Self::Unhashed
        } else if slot[..8] == [0; 8] {
            Self::Crc32(u32::from_be_bytes([slot[12], slot[13], slot[14], slot[15]]))
        } else {
            Self::Md5(slot)
        }
    }

    /// Fails unless `data` hashes to what was stored.
    pub(crate) fn check(self, data: &[u8]) -> Result<(), CodecError> {
        let (hash, matches) = match self {
            Self::Unhashed => return Ok(()),
            Self::Md5(want) => ("MD5", <[u8; 16]>::from(Md5::digest(data)) == want),
            Self::Crc32(want) => ("CRC-32", crc32fast::hash(data) == want),
        };
        snafu::ensure!(matches, codec_error::HashMismatch { hash });
        Ok(())
    }
}

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
    /// What the decoded bytes hash to.
    pub(crate) hash: Hash,
}

impl BlobRef {
    /// Decodes the blob, then checks its hash unless `verify` is off.
    pub(crate) fn decode(
        &self,
        raw: &[u8],
        limit: usize,
        verify: bool,
    ) -> Result<Vec<u8>, CodecError> {
        let expect = Expect {
            declared: self.declared.map(|n| n as usize),
            limit,
        };
        let out = match self.codec {
            Codec::Prefixed => codec::decode_prefixed(raw, expect),
            Codec::External(id) => codec::decode_external(id, raw, expect),
        }?;
        if verify {
            self.hash.check(&out)?;
        }
        Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    #[test]
    fn a_slot_names_its_hash_by_shape() {
        check!(Hash::from_slot([0; 16]) == Hash::Unhashed);
        let mut crc = [0u8; 16];
        crc[8..12].copy_from_slice(&5u32.to_be_bytes());
        crc[12..].copy_from_slice(&crc32fast::hash(b"hello").to_be_bytes());
        check!(Hash::from_slot(crc) == Hash::Crc32(crc32fast::hash(b"hello")));
        check!(let Hash::Md5(_) = Hash::from_slot([7; 16]));
    }

    #[test]
    fn each_hash_accepts_its_own_bytes_and_refuses_others() {
        let md5 = Hash::Md5(Md5::digest(b"hello").into());
        let crc = Hash::Crc32(crc32fast::hash(b"hello"));
        for hash in [md5, crc] {
            check!(hash.check(b"hello").is_ok());
            check!(let Err(CodecError::HashMismatch { .. }) = hash.check(b"hellp"));
        }
        check!(Hash::Unhashed.check(b"anything").is_ok());
    }
}
