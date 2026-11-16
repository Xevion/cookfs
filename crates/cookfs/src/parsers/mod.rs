//! Format-specific trailer parsers, each building a shared [`crate::page::Layout`].
//!
//! This is the only place a `CFS0002` versus `CFS0003` branch fires.
//! Everything downstream reads the normalized layout.

use snafu::Snafu;

use crate::bytes::BytesError;
use crate::codec::CodecError;
use crate::source::SourceError;

pub(crate) mod cfs0002;
pub(crate) mod cfs0003;

/// A trailer that does not describe a readable archive.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
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
        source: CodecError,
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
