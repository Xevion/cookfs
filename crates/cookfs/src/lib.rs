//! A reader for cookfs, the page-based Tcl virtual filesystem archive.
//!
//! cookfs ships in two structurally different formats sharing one directory
//! tree encoding: `CFS0002`, the frozen legacy format InstallBuilder
//! installers carry, and `CFS0003`, what upstream writes since 2024. Both
//! are read transparently.

mod bytes;
pub mod cache;
mod codec;
mod error;
mod index;
mod limits;
mod page;
mod parsers;
mod source;
mod wire;

use positioned_io::{ReadAt, Size};
use snafu::{OptionExt, ResultExt, ensure};

use error::error as ctx;
use index::Index;
use page::BlobRef;
use parsers::{cfs0002, cfs0003};

pub use bytes::BytesError;
pub use cache::{Budget, Page, PageCache};
pub use codec::CodecError;
pub use error::{Blob, Error, Result};
pub use index::{Block, Idx, IndexError, Kind, Node};
pub use limits::Limits;
pub use parsers::TrailerError;
pub use parsers::cfs0003::{Encryption, EncryptionMode};
pub use source::SourceError;
pub use wire::Compression;

/// Worker count assumed when the OS cannot report available parallelism.
const WORKERS_FALLBACK: usize = 4;

/// What [`Archive::open`] needs to know beyond the source.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Ceilings on what the archive's own bytes can make the reader allocate.
    pub limits: Limits,
}

/// Which trailer format an archive was opened as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveVersion {
    /// `CFS0002`: each blob names its codec in its first byte.
    Cfs0002,
    /// `CFS0003`: a pgindex names each page's codec.
    Cfs0003,
}

/// A cookfs archive opened over a random-access source.
///
/// The format is decided once, in [`Archive::open`]; every read after that
/// is version-blind. Pages decode on demand into a bounded cache, and nothing
/// beyond the trailer and the fsindex is read up front.
pub struct Archive<R> {
    src: R,
    version: ArchiveVersion,
    pages: Vec<BlobRef>,
    index: Index,
    cache: PageCache,
    limits: Limits,
    encryption: Option<Encryption>,
}

impl<R: ReadAt + Size> Archive<R> {
    /// Opens a `CFS0002` or `CFS0003` archive found anywhere in `src`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Trailer`] when no signature parses as a trailer,
    /// [`Error::Encrypted`] for an encrypted `CFS0003` archive, and any error
    /// reading the trailer, decoding the fsindex or parsing its tree.
    pub fn open(src: R, opts: &OpenOptions) -> Result<Self> {
        let limits = opts.limits;
        let len = src
            .size()
            .ok()
            .flatten()
            .context(source::source_error::NoLength)?;

        let (sig_at, which) = source::find_signature(
            &src,
            len,
            &[cfs0002::SIGNATURE, cfs0003::SIGNATURE],
            |at, idx| {
                if idx == 0 {
                    cfs0002::parse(&src, at).is_ok()
                } else {
                    cfs0003::Suffix::read(&src, at).is_ok_and(|s| s.fits_before(at))
                }
            },
        )?
        .context(parsers::trailer_error::NoSignature)?;

        let (layout, version) = if which == 0 {
            (cfs0002::parse(&src, sig_at)?, ArchiveVersion::Cfs0002)
        } else {
            (
                cfs0003::parse(&src, sig_at, &limits)?,
                ArchiveVersion::Cfs0003,
            )
        };

        if let Some(Encryption { mode, .. }) = layout.encryption {
            ensure!(mode == EncryptionMode::NONE, ctx::Encrypted { mode });
        }

        let index = match layout.fsindex {
            Some(blob) => {
                let raw = source::at(&src, blob.at, blob.len as usize)?;
                let plain = blob
                    .decode(&raw, limits.max_fsindex_len)
                    .context(ctx::Decode {
                        blob: Blob::Fsindex,
                    })?;
                Index::parse(&plain, limits.max_depth)?
            }
            None => Index::empty(),
        };
        check_blocks(&index, layout.pages.len())?;

        let sizes: Vec<u32> = layout
            .pages
            .iter()
            .map(|p| p.declared.unwrap_or(p.len))
            .collect();
        let workers = std::thread::available_parallelism()
            .map_or(WORKERS_FALLBACK, std::num::NonZeroUsize::get);

        Ok(Self {
            src,
            version,
            pages: layout.pages,
            index,
            cache: PageCache::new(Budget::from_pages(&sizes, workers)),
            limits,
            encryption: layout.encryption,
        })
    }

    /// Which trailer format this archive was opened as.
    #[must_use]
    pub const fn version(&self) -> ArchiveVersion {
        self.version
    }

    /// The `CFS0003` encryption mode and level, or `None` for `CFS0002`.
    #[must_use]
    pub const fn encryption(&self) -> Option<Encryption> {
        self.encryption
    }

    fn page(&self, n: u32) -> Result<Page> {
        let blob = *self.pages.get(n as usize).context(ctx::PageOutOfRange {
            page: n,
            pages: self.pages.len(),
        })?;
        self.cache.get_or_load(n as usize, || {
            let raw = source::at(&self.src, blob.at, blob.len as usize)?;
            blob.decode(&raw, self.limits.max_page_len)
                .context(ctx::Decode {
                    blob: Blob::Page(n),
                })
        })
    }

    /// Reads a file's full contents, or nothing for a directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when a page the file spans fails to decode, and
    /// [`Error::BlockOutOfPage`] when one of its blocks runs past its page.
    pub fn read(&self, node: Idx<Node>) -> Result<Vec<u8>> {
        let Kind::File(blocks) = &self.index.nodes[node].kind else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(self.index.nodes[node].size() as usize);
        for &Block { page, offset, size } in blocks {
            let data = self.page(page)?;
            let range = offset as usize..offset as usize + size as usize;
            let bytes = data.get(range).context(ctx::BlockOutOfPage {
                page,
                offset,
                size,
                page_len: data.len(),
            })?;
            out.extend_from_slice(bytes);
        }
        Ok(out)
    }

    /// Looks up a node by its handle.
    #[must_use]
    pub fn node(&self, node: Idx<Node>) -> &Node {
        &self.index.nodes[node]
    }

    /// Every node in pre-order, siblings sorted by name, with its full path.
    pub fn walk(&self) -> Vec<(String, Idx<Node>)> {
        self.index.walk()
    }
}

/// Refuses a tree that names a page the archive does not hold.
fn check_blocks(index: &Index, pages: usize) -> Result<()> {
    for (_, node) in index.nodes.iter() {
        if let Kind::File(blocks) = &node.kind
            && let Some(bad) = blocks.iter().find(|b| b.page as usize >= pages)
        {
            return ctx::PageOutOfRange {
                page: bad.page,
                pages,
            }
            .fail();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use index::tests::Fsindex;

    /// A stored `CFS0002` blob: id byte 0, then the payload.
    fn stored(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0u8];
        blob.extend_from_slice(payload);
        blob
    }

    fn open(buf: Vec<u8>) -> Result<Archive<Vec<u8>>> {
        Archive::open(buf, &OpenOptions::default())
    }

    /// One file, `hello.txt`, holding `payload` in page 0.
    fn one_file_v2(payload: &[u8]) -> Vec<u8> {
        let fsindex = Fsindex::new(1)
            .file("hello.txt", &[(0, 0, payload.len() as i32)])
            .finish();
        let page = (
            stored(payload),
            cfs0002::tests::crc_slot(payload.len() as u32),
        );
        cfs0002::tests::archive(&[page], &stored(&fsindex))
    }

    fn one_file_v3(payload: &[u8]) -> Vec<u8> {
        let fsindex = Fsindex::new(1)
            .file("hello.txt", &[(0, 0, payload.len() as i32)])
            .finish();
        cfs0003::tests::archive(&[payload.to_vec()], &fsindex, 0x78)
    }

    #[test]
    fn a_cfs0002_file_reads_back_its_bytes() {
        let archive = open(one_file_v2(b"hello world!")).unwrap();
        check!(archive.version() == ArchiveVersion::Cfs0002);
        check!(archive.encryption().is_none());
        let (path, idx) = archive.walk().into_iter().next().unwrap();
        check!(path == "hello.txt");
        check!(archive.read(idx).unwrap() == b"hello world!");
    }

    #[test]
    fn a_cfs0003_file_reads_back_its_bytes() {
        let archive = open(one_file_v3(b"hello v3!")).unwrap();
        check!(archive.version() == ArchiveVersion::Cfs0003);
        check!(
            archive.encryption()
                == Some(Encryption {
                    mode: EncryptionMode::NONE,
                    level: 15
                })
        );
        let (_, idx) = archive.walk().into_iter().next().unwrap();
        check!(archive.read(idx).unwrap() == b"hello v3!");
    }

    #[test]
    fn an_encrypted_cfs0003_archive_is_refused_rather_than_misread() {
        let fsindex = Fsindex::new(0).finish();
        let buf = cfs0003::tests::archive(&[], &fsindex, 0x79);
        check!(let Err(Error::Encrypted { mode: EncryptionMode::FILE }) = open(buf));
    }

    #[test]
    fn a_source_without_a_signature_is_refused() {
        check!(let Err(Error::Trailer { source: TrailerError::NoSignature }) = open(vec![0u8; 32]));
    }

    #[test]
    fn a_block_naming_a_missing_page_is_refused_at_open() {
        let fsindex = Fsindex::new(1).file("f", &[(5, 0, 1)]).finish();
        let buf = cfs0002::tests::archive(&[], &stored(&fsindex));
        check!(let Err(Error::PageOutOfRange { page: 5, pages: 0 }) = open(buf));
    }

    #[test]
    fn a_block_running_past_its_page_is_an_error() {
        let fsindex = Fsindex::new(1).file("f", &[(0, 8, 9)]).finish();
        let page = (stored(b"0123456789"), cfs0002::tests::crc_slot(10));
        let archive = open(cfs0002::tests::archive(&[page], &stored(&fsindex))).unwrap();
        let (_, idx) = archive.walk().into_iter().next().unwrap();
        check!(let Err(Error::BlockOutOfPage { page: 0, page_len: 10, .. }) = archive.read(idx));
    }

    #[test]
    fn an_fsindex_over_the_limit_is_refused() {
        let opts = OpenOptions {
            limits: Limits {
                max_fsindex_len: 4,
                ..Limits::default()
            },
        };
        let check = Archive::open(one_file_v2(b"x"), &opts);
        check!(let Err(Error::Decode { blob: Blob::Fsindex, source: CodecError::TooLarge { limit: 4, .. } }) = check);
    }
}
