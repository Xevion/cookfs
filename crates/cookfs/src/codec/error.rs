//! The error every stage of decoding a blob reports.

use snafu::Snafu;

use crate::wire::Compression;

/// A blob that could not be decrypted, decoded or verified.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum DecodeError {
    /// The id names no codec this crate knows.
    #[snafu(display("unknown compression id {}", id.raw()))]
    Unknown {
        /// The id as read.
        id: Compression,
    },
    /// The codec is known but cannot be decoded by this build.
    #[snafu(display("{id} decoding is not available: {why}"))]
    Unavailable {
        /// The codec.
        id: Compression,
        /// What would make it available.
        why: &'static str,
    },
    /// A `CFS0002` blob had no leading id byte.
    #[snafu(display("blob is empty, so it has no compression id"))]
    Empty,
    /// A legacy bzip2 blob ends before the decoded size it must carry.
    #[snafu(display("bzip2 blob is too short to hold its size prefix"))]
    NoSizePrefix,
    /// The codec rejected the payload.
    #[snafu(display("{id} payload failed to decode"))]
    Decompress {
        /// The codec.
        id: Compression,
        /// The decoder's failure.
        source: std::io::Error,
    },
    /// The output would exceed its declared size or the configured limit.
    #[snafu(display("{id} output exceeds {limit} bytes"))]
    TooLarge {
        /// The codec.
        id: Compression,
        /// The ceiling that was hit.
        limit: usize,
    },
    /// The output stopped short of the size the archive declared for it.
    #[snafu(display("{id} output is {got} bytes, the archive declares {want}"))]
    Short {
        /// The codec.
        id: Compression,
        /// The declared size.
        want: usize,
        /// The size actually produced.
        got: usize,
    },
    /// An encrypted blob did not decrypt.
    #[snafu(display("blob did not decrypt: {why}"))]
    Decrypt {
        /// What was wrong with it.
        why: &'static str,
    },
    /// The decoded bytes do not hash to what the archive stored for them.
    #[snafu(display("decoded bytes fail their {hash} check"))]
    HashMismatch {
        /// Which hash the archive stored.
        hash: &'static str,
    },
    /// Raw LZMA1 has no end marker, so it cannot be decoded without a declared size.
    #[snafu(display("{id} blob has no declared size to stop at"))]
    Unbounded {
        /// The codec.
        id: Compression,
    },
}

const _: () = assert!(size_of::<DecodeError>() <= 64);
