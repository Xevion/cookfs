//! A reader for cookfs, the page-based Tcl virtual filesystem archive.
//!
//! cookfs ships in two structurally different formats sharing one directory
//! tree encoding: `CFS0002`, the frozen legacy format InstallBuilder
//! installers carry, and `CFS0003`, what upstream writes since 2024. Both
//! are read transparently.
//!
//! ```no_run
//! use std::fs::File;
//!
//! use cookfs::{Archive, OpenOptions};
//!
//! let archive = Archive::open(File::open("installer.run")?, &OpenOptions::default())?;
//! // Data order decodes each page once; path order can decode one many times.
//! for (path, id) in archive.page_order() {
//!     // Names are whatever upstream stored, so refuse any that could escape the output.
//!     if archive.has_portable_path(id) {
//!         let contents = archive.read(id)?;
//!         println!("{path}: {} bytes", contents.len());
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod archive;
mod blob;
mod bytes;
mod cache;
mod codec;
mod crypto;
mod error;
mod file;
mod index;
mod limits;
mod name;
mod parsers;
mod source;
#[cfg(test)]
mod tests;
mod wire;

pub use archive::{Archive, ArchiveVersion, OpenOptions};
pub use bytes::BytesError;
pub use codec::DecodeError;
pub use crypto::{Encryption, EncryptionMode};
pub use error::{Blob, Error, Result};
pub use file::FileReader;
pub use index::{Block, IndexError, Kind, Node, NodeId, Walk};
pub use limits::Limits;
pub use parsers::TrailerError;
pub use source::SourceError;
pub use wire::Compression;

/// Entry points for the fuzz targets into parsers the public API does not expose.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    /// Parses `data` as a decoded fsindex.
    pub fn fsindex(data: &[u8]) {
        let _ = crate::index::Index::parse(data, 64);
    }

    /// Parses `data` as a decoded `CFS0003` pgindex.
    pub fn pgindex(data: &[u8]) {
        let _ = crate::parsers::cfs0003::page_table(data, u64::MAX);
    }

    /// Decodes `body` with the codec `id` names, as a `CFS0003` page would be.
    ///
    /// # Errors
    ///
    /// Whatever the codec reports.
    pub fn decode(
        id: u8,
        body: &[u8],
        declared: Option<usize>,
        limit: usize,
    ) -> Result<Vec<u8>, crate::DecodeError> {
        let expect = crate::codec::Expect { declared, limit };
        crate::codec::decode(crate::wire::Compression::from_raw(id), body, expect)
    }
}
