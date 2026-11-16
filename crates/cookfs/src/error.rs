//! The crate's public error, wrapping each module's own.

use std::fmt;

use snafu::Snafu;

use crate::codec::CodecError;
use crate::index::IndexError;
use crate::parsers::TrailerError;
use crate::parsers::cfs0003::EncryptionMode;
use crate::source::SourceError;

/// Which blob a decode failure belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Blob {
    /// A data page, by index.
    Page(u32),
    /// The fsindex.
    Fsindex,
}

impl fmt::Display for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Page(n) => write!(f, "page {n}"),
            Self::Fsindex => f.write_str("fsindex"),
        }
    }
}

/// Everything that can go wrong reading a cookfs archive.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum Error {
    /// Reading the source failed.
    #[snafu(transparent)]
    Source {
        /// The underlying failure.
        source: SourceError,
    },
    /// The trailer does not describe a readable archive.
    #[snafu(transparent)]
    Trailer {
        /// What is wrong with it.
        source: TrailerError,
    },
    /// The fsindex does not describe a valid tree.
    #[snafu(transparent)]
    Index {
        /// What is wrong with it.
        source: IndexError,
    },
    /// A page or the fsindex did not decode.
    #[snafu(display("{blob} could not be decoded"))]
    Decode {
        /// Which blob.
        blob: Blob,
        /// The decoder's failure.
        source: CodecError,
    },
    /// The archive is encrypted, which this reader does not yet decrypt.
    #[snafu(display("archive is encrypted ({mode})"))]
    Encrypted {
        /// The archive's encryption mode.
        mode: EncryptionMode,
    },
    /// A page is flagged as encrypted in an archive whose suffix says it is not.
    #[snafu(display("page {page} is flagged as encrypted"))]
    EncryptedPage {
        /// The page.
        page: u32,
    },
    /// A file is larger than [`crate::Limits::max_file_len`] allows reading whole.
    #[snafu(display("file of {size} bytes exceeds the {limit}-byte limit"))]
    FileTooLarge {
        /// The sum of the file's blocks.
        size: u64,
        /// The configured ceiling.
        limit: u64,
    },
    /// A file's blocks make the reader decode far more than the file holds.
    ///
    /// A file written in order decodes each page it spans about once. Blocks
    /// cycling through pages can instead force a decode per block.
    #[snafu(display("file of {size} bytes needed {decoded} decoded bytes and counting"))]
    Overdecoded {
        /// The sum of the file's blocks.
        size: u64,
        /// Decoded page bytes consumed when the read stopped.
        decoded: u64,
    },
    /// A file names a page the archive does not have.
    #[snafu(display("a file names page {page}, but the archive holds {pages}"))]
    PageOutOfRange {
        /// The page named.
        page: u32,
        /// How many pages the archive holds.
        pages: usize,
    },
    /// A block runs past the end of its decoded page.
    #[snafu(display(
        "block at offset {offset} of {size} bytes runs past page {page}, which is {page_len} bytes"
    ))]
    BlockOutOfPage {
        /// The page.
        page: u32,
        /// The block's offset into it.
        offset: u32,
        /// The block's length.
        size: u32,
        /// The decoded page's length.
        page_len: usize,
    },
}

const _: () = assert!(size_of::<Error>() <= 64);

/// The crate's result type.
pub type Result<T, E = Error> = std::result::Result<T, E>;
