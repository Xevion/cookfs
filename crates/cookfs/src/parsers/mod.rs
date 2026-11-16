//! Format-specific trailer parsers, each building a shared [`Layout`].
//!
//! This is the only place a `CFS0002` versus `CFS0003` branch fires.
//! Everything downstream reads the normalized layout.

use snafu::Snafu;

use crate::blob::BlobRef;
use crate::bytes::BytesError;
use crate::codec::DecodeError;
use crate::crypto::Encryption;
use crate::source::SourceError;

pub(crate) mod cfs0002;
pub(crate) mod cfs0003;

/// Everything [`crate::Archive::open`] needs once a format parser has run.
#[derive(Debug)]
pub(crate) struct Layout {
    /// Every data page, in page-index order.
    pub(crate) pages: Vec<BlobRef>,
    /// The fsindex blob.
    pub(crate) fsindex: BlobRef,
    /// The `CFS0003` encryption byte; `CFS0002` has none.
    pub(crate) encryption: Option<Encryption>,
}

/// A trailer that does not describe a readable archive.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum TrailerError {
    /// No known signature parsed as a trailer anywhere in the source.
    #[snafu(display("no cookfs signature found"))]
    NoSignature,
    /// A region the trailer describes would start before the source does.
    #[snafu(display("{region} of {len} bytes does not fit before offset {end}"))]
    Underflow {
        /// What the region holds.
        region: &'static str,
        /// The region's length as the trailer records it.
        len: u64,
        /// Where the region must end.
        end: u64,
    },
    /// A region is larger than this platform can address.
    #[snafu(display("{region} of {len} bytes does not fit in memory"))]
    Oversized {
        /// What the region holds.
        region: &'static str,
        /// The region's length as the trailer records it.
        len: u64,
    },
    /// The trailer records no fsindex, which every archive upstream writes has.
    #[snafu(display("trailer records an empty fsindex"))]
    NoFsindex,
    /// Reading a trailer region failed.
    #[snafu(display("trailer region could not be read"))]
    Read {
        /// The underlying failure.
        source: SourceError,
    },
    /// The `CFS0003` pgindex blob did not decode.
    #[snafu(display("pgindex could not be decoded"))]
    PgindexBlob {
        /// The decoder's failure.
        source: DecodeError,
    },
    /// The decoded `CFS0003` pgindex is longer than its own page count allows.
    #[snafu(display("pgindex has {extra} bytes after its last record"))]
    PgindexTrailing {
        /// How many bytes were left unread.
        extra: usize,
    },
    /// The decoded `CFS0003` pgindex is shorter than its own page count requires.
    #[snafu(display("pgindex is truncated"))]
    PgindexLayout {
        /// Where the read failed.
        source: BytesError,
    },
}

const _: () = assert!(size_of::<TrailerError>() <= 64);

/// The offset `len` bytes before `end`, or an underflow naming the region.
fn before(region: &'static str, end: u64, len: u64) -> Result<u64, TrailerError> {
    end.checked_sub(len)
        .ok_or(TrailerError::Underflow { region, len, end })
}

/// A region length the trailer records, as a length this platform can allocate.
fn addressable(region: &'static str, len: u64) -> Result<usize, TrailerError> {
    usize::try_from(len).map_err(|_| TrailerError::Oversized { region, len })
}
