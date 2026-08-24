//! cookfs, the page-based Tcl virtual filesystem archive format.

pub mod cache;
mod codec;
mod index;
mod page;
mod parsers;
mod read;

use positioned_io::{ReadAt, Size};
use snafu::OptionExt;

use index::Index;
use page::{PageCodec, PageTable};
use read::{BadBlockSnafu, NoLengthSnafu, PageOutOfRangeSnafu};

pub use cache::{Budget, Page, PageCache};
/// Compression codec named by a blob's leading id byte, or an explicit id.
pub use codec::Codec;
/// One compressed byte range that a file's contents span.
pub use index::Block;
/// An arena handle to a [`Node`].
pub use index::Idx;
/// What a node in the tree is: a directory of children, or a file's blocks.
pub use index::Kind;
/// One entry in the fsindex tree: a file or a directory.
pub use index::Node;
/// Everything that can go wrong reading a cookfs archive.
pub use read::Error;
/// The crate's result type, defaulting to [`Error`].
pub use read::Result;

/// Worker count assumed when the OS cannot report available parallelism.
const WORKERS_FALLBACK: usize = 4;

/// Which cookfs trailer format an archive was opened as.
///
/// Both formats share one directory-tree encoding; this only names the
/// difference in trailer shape and how a page's codec is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveVersion {
    /// `CFS0002`: one archive-wide codec byte, per-page id in each blob's
    /// leading byte.
    Cfs0002,
    /// `CFS0003`: per-page codec named explicitly in a separate pgindex table.
    Cfs0003,
}

/// A cookfs archive opened over a random-access source.
///
/// Reads `CFS0002` and `CFS0003` transparently: the format is decided once,
/// during [`Archive::open`], and every read afterward is version-blind.
/// Pages are decompressed on demand and held in a bounded cache; nothing is
/// read up front beyond the trailer and the fsindex.
pub struct Archive<R> {
    src: R,
    version: ArchiveVersion,
    pages: PageTable,
    index: Index,
    cache: PageCache,
    encryption: Option<u8>,
}

impl<R: ReadAt + Size> Archive<R> {
    /// Opens a `CFS0002` or `CFS0003` archive, parsing its trailer and
    /// directory tree.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoLength`] if `src` cannot report its size,
    /// [`Error::NoSignature`] if no known trailer parses anywhere in it, or
    /// any error a format-specific parser or the fsindex parser can produce.
    pub fn open(src: R) -> Result<Self> {
        let len = src.size().ok().flatten().context(NoLengthSnafu)?;

        let (sig_at, which) = read::find_signature(
            &src,
            len,
            &[parsers::cfs0002::SIGNATURE, parsers::cfs0003::SIGNATURE],
            |candidate, idx| {
                if idx == 0 {
                    parsers::cfs0002::parse(&src, candidate).is_ok()
                } else {
                    parsers::cfs0003::Trailer::parse(&src, candidate).is_ok()
                }
            },
        )?;

        let (layout, version) = if which == 0 {
            (
                parsers::cfs0002::parse(&src, sig_at)?,
                ArchiveVersion::Cfs0002,
            )
        } else {
            (
                parsers::cfs0003::parse(&src, sig_at)?,
                ArchiveVersion::Cfs0003,
            )
        };

        let raw = read::at(&src, layout.fsindex_at, layout.fsindex_len)?;
        // CFS0002 declares no fsindex uncompressed size; only a raw LZMA1
        // blob needs one to bound its read, and CFS0002 never emits one here.
        let fsindex_uncompressed_len = layout.fsindex_uncompressed_len.unwrap_or(u32::MAX);
        let index = Index::parse(&decode_page(
            &raw,
            layout.fsindex_codec,
            fsindex_uncompressed_len,
        )?)?;

        let uncompressed: Vec<u32> = layout
            .pages
            .entries
            .iter()
            .map(|e| e.uncompressed_len)
            .collect();
        let workers = std::thread::available_parallelism()
            .map_or(WORKERS_FALLBACK, std::num::NonZeroUsize::get);
        let cache = PageCache::new(Budget::from_pages(&uncompressed, workers));

        Ok(Self {
            src,
            version,
            pages: layout.pages,
            index,
            cache,
            encryption: layout.encryption,
        })
    }

    /// Which on-disk trailer format this archive was opened as.
    #[must_use]
    pub fn version(&self) -> ArchiveVersion {
        self.version
    }

    /// `CFS0003`'s encryption byte, or `None` for a `CFS0002` archive, which
    /// has none.
    ///
    /// Semantics are unconfirmed upstream; both known samples read `0x78`
    /// and upstream Tcl does not gate behavior on this value. Treat a
    /// non-zero value as a signal to investigate, not as an error.
    #[must_use]
    pub fn encryption(&self) -> Option<u8> {
        self.encryption
    }

    fn page(&self, n: usize) -> Result<Page> {
        let entry = *self.pages.entries.get(n).context(PageOutOfRangeSnafu {
            page: n,
            pages: self.pages.entries.len(),
        })?;
        self.cache.get_or_load(n, || {
            let raw = read::at(&self.src, entry.offset, entry.compressed_len as usize)?;
            decode_page(&raw, entry.codec, entry.uncompressed_len)
        })
    }

    /// Reads a file node's full decompressed contents.
    ///
    /// Returns an empty vector for a directory node.
    ///
    /// # Errors
    ///
    /// Returns any error the page cache or a page's codec can produce.
    pub fn read(&self, node: Idx<Node>) -> Result<Vec<u8>> {
        let Kind::File(blocks) = &self.index.nodes[node].kind else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(self.index.nodes[node].size() as usize);
        for &block in blocks {
            snafu::ensure!(
                block.page >= 0 && block.offset >= 0 && block.size >= 0,
                BadBlockSnafu {
                    page: block.page,
                    offset: block.offset,
                    size: block.size,
                }
            );
            let page = self.page(block.page as usize)?;
            let start = (block.offset as usize).min(page.len());
            let end = (start + block.size as usize).min(page.len());
            out.extend_from_slice(&page[start..end]);
        }
        Ok(out)
    }

    /// Looks up a node by its arena handle.
    #[must_use]
    pub fn node(&self, node: Idx<Node>) -> &Node {
        &self.index.nodes[node]
    }

    /// Walks the directory tree depth-first, yielding each node's full path.
    pub fn walk(&self) -> Vec<(String, Idx<Node>)> {
        self.index.walk()
    }
}

/// Decodes a page or fsindex blob per its normalized [`PageCodec`].
///
/// This is the one place `CFS0002`'s leading-byte convention and `CFS0003`'s
/// externally-named codec converge: everywhere else, a blob just has a
/// [`PageCodec`] and this function is how it gets decoded. `uncompressed_len`
/// is the blob's own declared decompressed size, needed only to bound a raw
/// LZMA1 stream that carries no end-of-stream marker of its own.
fn decode_page(blob: &[u8], codec: PageCodec, uncompressed_len: u32) -> Result<Vec<u8>> {
    let uncompressed_len = uncompressed_len as usize;
    match codec {
        PageCodec::Prefixed => codec::decode(blob, uncompressed_len),
        PageCodec::External(id) => codec::decode_with(id, blob, uncompressed_len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    /// A codec-`Stored` blob: a leading id byte of 0, then the payload as-is.
    fn stored(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0u8];
        blob.extend_from_slice(payload);
        blob
    }

    fn file_entry(name: &str, block: Block) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(&0i64.to_be_bytes()); // mtime
        out.extend_from_slice(&1i32.to_be_bytes()); // one block
        out.extend_from_slice(&block.page.to_be_bytes());
        out.extend_from_slice(&block.offset.to_be_bytes());
        out.extend_from_slice(&block.size.to_be_bytes());
        out
    }

    /// Builds a complete, minimal CFS0002 archive holding one file at the
    /// root, everything encoded with the `Stored` codec.
    fn one_file_archive() -> (Vec<u8>, Vec<u8>) {
        let payload = b"hello world!".to_vec();
        let page = stored(&payload);

        let file = file_entry(
            "hello.txt",
            Block {
                page: 0,
                offset: 0,
                size: payload.len() as i32,
            },
        );
        let mut fsindex_plain = read::FSINDEX_MAGIC.to_vec();
        fsindex_plain.extend_from_slice(&1u32.to_be_bytes()); // root has one child
        fsindex_plain.extend_from_slice(&file);
        fsindex_plain.extend_from_slice(&0u32.to_be_bytes()); // zero metadata records
        let fsindex = stored(&fsindex_plain);

        let mut buf = Vec::new();
        buf.extend_from_slice(&page); // pages_at == 0

        let mut meta = vec![0u8; 16];
        meta[8..12].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&meta);

        buf.extend_from_slice(&(page.len() as u32).to_be_bytes());

        buf.extend_from_slice(&fsindex);

        buf.extend_from_slice(&(fsindex.len() as u32).to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // page_count
        buf.push(0); // archive-wide codec, informational only

        buf.extend_from_slice(parsers::cfs0002::SIGNATURE);

        (buf, payload)
    }

    /// Builds a complete, minimal CFS0003 archive holding one file at the
    /// root, everything encoded with the `Stored` codec.
    fn one_file_archive_v3() -> (Vec<u8>, Vec<u8>) {
        let payload = b"hello v3!".to_vec();
        let page = payload.clone(); // Stored: no leading id byte at all

        let file = file_entry(
            "hello.txt",
            Block {
                page: 0,
                offset: 0,
                size: payload.len() as i32,
            },
        );
        let mut fsindex_plain = read::FSINDEX_MAGIC.to_vec();
        fsindex_plain.extend_from_slice(&1u32.to_be_bytes());
        fsindex_plain.extend_from_slice(&file);
        fsindex_plain.extend_from_slice(&0u32.to_be_bytes());
        let fsindex = fsindex_plain;

        let mut pgindex = 1u32.to_be_bytes().to_vec();
        pgindex.push(0); // comprlist: Stored
        pgindex.push(0); // comprlevellist
        pgindex.push(0); // encryptionlist
        pgindex.extend_from_slice(&(page.len() as u32).to_be_bytes());
        pgindex.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        pgindex.extend_from_slice(&[0u8; 16]); // md5

        let mut buf = Vec::new();
        buf.extend_from_slice(&page); // pages_at == 0
        buf.extend_from_slice(&pgindex);
        buf.extend_from_slice(&fsindex);

        buf.push(0); // base_compression
        buf.push(0); // base_compression_level
        buf.push(0x78); // encryption
        buf.push(0); // pgindex_compression: Stored
        buf.push(0); // pgindex_compression_level
        buf.extend_from_slice(&[0u8; 16]); // pgindex_md5
        buf.extend_from_slice(&(pgindex.len() as u32).to_be_bytes());
        buf.extend_from_slice(&(pgindex.len() as u32).to_be_bytes());
        buf.push(0); // fsindex_compression: Stored
        buf.push(0); // fsindex_compression_level
        buf.extend_from_slice(&[0u8; 16]); // fsindex_md5
        buf.extend_from_slice(&(fsindex.len() as u32).to_be_bytes());
        buf.extend_from_slice(&(fsindex.len() as u32).to_be_bytes());

        buf.extend_from_slice(parsers::cfs0003::SIGNATURE);

        (buf, payload)
    }

    #[test]
    fn open_reads_the_trailer_and_walks_the_one_file_it_holds() {
        let (buf, _) = one_file_archive();
        let archive = Archive::open(buf).unwrap();

        let paths: Vec<String> = archive.walk().into_iter().map(|(path, _)| path).collect();
        check!(paths == vec!["hello.txt".to_owned()]);
    }

    #[test]
    fn read_returns_the_files_decompressed_bytes() {
        let (buf, payload) = one_file_archive();
        let archive = Archive::open(buf).unwrap();

        let (_, idx) = archive.walk().into_iter().next().unwrap();
        check!(archive.read(idx).unwrap() == payload);
    }

    #[test]
    fn node_looks_up_the_file_by_its_handle() {
        let (buf, payload) = one_file_archive();
        let archive = Archive::open(buf).unwrap();

        let (_, idx) = archive.walk().into_iter().next().unwrap();
        let node = archive.node(idx);
        check!(!node.is_dir());
        check!(node.size() == payload.len() as u64);
    }

    #[test]
    fn open_fails_without_a_signature() {
        check!(let Err(Error::NoSignature) = Archive::open(vec![0u8; 32]));
    }

    /// A corrupted archive could hand a caller a block with a negative field;
    /// the raw `i32 as usize` cast would wrap into a huge value and panic.
    #[test]
    fn read_rejects_a_block_with_a_negative_field() {
        let (buf, _) = one_file_archive();
        let mut archive = Archive::open(buf).unwrap();

        let root = archive.index.root;
        let bad = archive.index.nodes.alloc(Node {
            name: "bad".to_owned(),
            mtime: 0,
            parent: Some(root),
            kind: Kind::File(vec![Block {
                page: 0,
                offset: -1,
                size: 4,
            }]),
        });

        check!(let Err(Error::BadBlock { .. }) = archive.read(bad));
    }

    #[test]
    fn open_reads_a_cfs0003_archive_and_walks_its_one_file() {
        let (buf, _) = one_file_archive_v3();
        let archive = Archive::open(buf).unwrap();

        check!(archive.version() == ArchiveVersion::Cfs0003);
        let paths: Vec<String> = archive.walk().into_iter().map(|(path, _)| path).collect();
        check!(paths == vec!["hello.txt".to_owned()]);
    }

    #[test]
    fn read_returns_a_cfs0003_files_decompressed_bytes() {
        let (buf, payload) = one_file_archive_v3();
        let archive = Archive::open(buf).unwrap();

        let (_, idx) = archive.walk().into_iter().next().unwrap();
        check!(archive.read(idx).unwrap() == payload);
    }

    #[test]
    fn a_cfs0002_archive_reports_its_own_version_and_no_encryption_byte() {
        let (buf, _) = one_file_archive();
        let archive = Archive::open(buf).unwrap();

        check!(archive.version() == ArchiveVersion::Cfs0002);
        check!(archive.encryption().is_none());
    }

    #[test]
    fn a_cfs0003_archive_reports_its_own_version_and_encryption_byte() {
        let (buf, _) = one_file_archive_v3();
        let archive = Archive::open(buf).unwrap();

        check!(archive.version() == ArchiveVersion::Cfs0003);
        check!(archive.encryption() == Some(0x78));
    }

    /// A crafted block naming a page past the archive's page count would
    /// index `self.pages.entries` out of range and panic.
    #[test]
    fn read_rejects_a_block_naming_a_page_past_the_archive() {
        let (buf, _) = one_file_archive();
        let mut archive = Archive::open(buf).unwrap();

        let root = archive.index.root;
        let bad = archive.index.nodes.alloc(Node {
            name: "bad".to_owned(),
            mtime: 0,
            parent: Some(root),
            kind: Kind::File(vec![Block {
                page: 42,
                offset: 0,
                size: 4,
            }]),
        });

        check!(let Err(Error::PageOutOfRange { .. }) = archive.read(bad));
    }

    /// A crafted block whose offset runs past the page would slice-index the
    /// page with `start > page.len()` and panic on the range.
    #[test]
    fn read_survives_a_block_whose_offset_runs_past_the_page() {
        let (buf, _) = one_file_archive();
        let mut archive = Archive::open(buf).unwrap();

        let root = archive.index.root;
        let bad = archive.index.nodes.alloc(Node {
            name: "bad".to_owned(),
            mtime: 0,
            parent: Some(root),
            kind: Kind::File(vec![Block {
                page: 0,
                offset: 9_999,
                size: 4,
            }]),
        });

        check!(archive.read(bad).unwrap().is_empty());
    }
}
