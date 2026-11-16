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
mod wire;

use positioned_io::{ReadAt, Size};
use snafu::{OptionExt, ResultExt, ensure};

use blob::BlobRef;
use cache::{Budget, Page, PageCache};
use crypto::Key;
use error::error as ctx;
use index::Index;
use parsers::{cfs0002, cfs0003};

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

/// The most [`Archive::read`] reserves at once ahead of the bytes it has copied.
const READ_RESERVE_STEP: usize = 64 << 20;

/// Worker count assumed when the OS cannot report available parallelism.
const WORKERS_FALLBACK: usize = 4;

/// What [`Archive::open`] needs to know beyond the source.
#[derive(Clone)]
#[non_exhaustive]
pub struct OpenOptions {
    /// Ceilings on what the archive's own bytes can make the reader allocate.
    pub limits: Limits,
    /// Whether every page and index is checked against the hash the archive stores for it.
    ///
    /// On by default. Upstream writes an MD5 or CRC-32 of each decoded blob;
    /// one written without a hash is never checked either way.
    pub verify: bool,
    password: Option<Vec<u8>>,
}

impl OpenOptions {
    /// Opens an encrypted `CFS0003` archive with `password`.
    ///
    /// Upstream derives the key from the password's bytes as Tcl holds them,
    /// which for a password beyond Latin-1 is not its UTF-8 encoding.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(password.into());
        self
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            verify: true,
            password: None,
        }
    }
}

impl std::fmt::Debug for OpenOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenOptions")
            .field("limits", &self.limits)
            .field("verify", &self.verify)
            .field("password", &self.password.as_ref().map(|_| ".."))
            .finish()
    }
}

/// Which trailer format an archive was opened as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    pub(crate) limits: Limits,
    verify: bool,
    encryption: Option<Encryption>,
    key: Option<Key>,
    /// The fileset directory standing in for the root, when the archive has filesets.
    fileset: Option<NodeId>,
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

        // A candidate that passes the cheap check but fails to open may be a decoy
        // after the real archive, so the scan goes on, a bounded number of times.
        let mut attempts = 0;
        let mut first_error = None;
        let mut opened = None;
        source::find_signature(
            &src,
            len,
            &[cfs0002::SIGNATURE, cfs0003::SIGNATURE],
            |at, idx| {
                let plausible = if idx == 0 {
                    cfs0002::plausible(&src, at)
                } else {
                    cfs0003::Suffix::read(&src, at).is_ok_and(|s| s.plausible(at))
                };
                if !plausible || attempts == MAX_OPEN_ATTEMPTS {
                    return false;
                }
                attempts += 1;
                match assemble(&src, at, idx, opts) {
                    Ok(found) => {
                        opened = Some(found);
                        true
                    }
                    Err(e) => {
                        first_error.get_or_insert(e);
                        false
                    }
                }
            },
        )?;
        let Assembled {
            layout,
            version,
            index,
            key,
        } = match (opened, first_error) {
            (Some(found), _) => found,
            (None, Some(e)) => return Err(e),
            (None, None) => return parsers::trailer_error::NoSignature.fail()?,
        };

        let sizes: Vec<u32> = layout
            .pages
            .iter()
            .map(|p| p.declared.unwrap_or(p.len))
            .collect();
        let workers = std::thread::available_parallelism()
            .map_or(WORKERS_FALLBACK, std::num::NonZeroUsize::get);

        let fileset = default_fileset(&index);
        Ok(Self {
            src,
            version,
            pages: layout.pages,
            index,
            cache: PageCache::new(Budget::from_pages(&sizes, workers)),
            limits,
            verify: opts.verify,
            encryption: layout.encryption,
            key,
            fileset,
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

    pub(crate) fn page(&self, n: u32) -> Result<Page> {
        let blob = *self.pages.get(n as usize).context(ctx::PageOutOfRange {
            page: n,
            pages: self.pages.len(),
        })?;
        ensure!(
            !blob.encrypted || self.key.is_some(),
            ctx::EncryptedPage { page: n }
        );
        self.cache.get_or_load(n as usize, || {
            let raw = source::at(&self.src, blob.at, blob.len as usize)?;
            blob.decode(
                &raw,
                self.limits.max_page_len,
                self.verify,
                self.key.as_ref(),
            )
            .context(ctx::Decode {
                blob: Blob::Page(n),
            })
        })
    }

    /// Reads a file's full contents.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAFile`] for a directory, [`Error::FileTooLarge`]
    /// past [`Limits::max_file_len`], [`Error::Decode`] when a page the file
    /// spans fails to decode, [`Error::BlockOutOfPage`] when one of its blocks
    /// runs past its page, and [`Error::Overdecoded`] when its blocks revisit
    /// pages far more than a file written in order does.
    pub fn read(&self, id: NodeId) -> Result<Vec<u8>> {
        let mut reader = self.open_file(id)?;
        let size = reader.len();
        let limit = self.limits.max_file_len;
        ensure!(size <= limit, ctx::FileTooLarge { size, limit });
        let mut out = Vec::new();
        while let Some((page, range)) = reader.chunk()? {
            // Reserved once a page has decoded, in bounded steps, so a size the fsindex
            // merely claims cannot reserve memory no page backs.
            if out.capacity() - out.len() < range.len() {
                let rest = usize::try_from(size).unwrap_or(usize::MAX) - out.len();
                out.reserve_exact(rest.min(READ_RESERVE_STEP).max(range.len()));
            }
            out.extend_from_slice(&page[range.clone()]);
            reader.advance(range.len());
        }
        Ok(out)
    }

    /// Opens a file's contents as a stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAFile`] for a directory. Reading the stream fails
    /// as [`Self::read`] does, apart from the size limit.
    pub fn open_file(&self, id: NodeId) -> Result<FileReader<'_, R>> {
        match &self.index.nodes[id].kind {
            Kind::File(blocks) => Ok(FileReader::new(self, blocks)),
            _ => ctx::NotAFile.fail(),
        }
    }

    /// Looks up a node by its handle.
    ///
    /// # Panics
    ///
    /// If `id` came from another archive and is out of this one's range.
    #[must_use]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.index.nodes[id]
    }

    /// Whether every name from [`Self::root`] down to `id` is safe as a path component on disk.
    ///
    /// See [`Node::has_portable_name`]. Checking only the entry's own name
    /// would miss a directory above it named `..`.
    #[must_use]
    pub fn has_portable_path(&self, id: NodeId) -> bool {
        let root = self.root();
        let mut at = id;
        while at != root {
            let node = self.node(at);
            if !node.has_portable_name() {
                return false;
            }
            match node.parent {
                Some(parent) => at = parent,
                None => return false,
            }
        }
        true
    }

    /// The directory paths are relative to: the active fileset, or the archive's root.
    #[must_use]
    pub fn root(&self) -> NodeId {
        self.fileset.unwrap_or(self.index.root)
    }

    /// The entry at `path`, its names joined by `/`, relative to [`Self::root`].
    ///
    /// The empty path is the root. Like upstream, this cannot reach an entry
    /// whose own name holds a `/`; [`Self::walk`] still lists it.
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<NodeId> {
        let mut at = self.root();
        if path.is_empty() {
            return Some(at);
        }
        for part in path.split('/') {
            let children = self.node(at).children();
            let found = children
                .binary_search_by(|&c| self.index.nodes[c].name.as_str().cmp(part))
                .ok()?;
            at = children[found];
        }
        Some(at)
    }

    /// Every entry under [`Self::root`] in pre-order, siblings sorted by name, with its path.
    pub fn walk(&self) -> Walk<'_> {
        self.index.walk(self.root())
    }

    /// Every file under [`Self::root`] with its path, in the order its data sits in the archive.
    ///
    /// Reading in this order decodes each page about once. Path order can
    /// switch pages hundreds of times in a large archive, and pages past the
    /// cache's budget then decode again on every return. An [`Archive`] over a
    /// `Sync` source is `Sync`, so splitting this list into runs across threads
    /// decodes pages in parallel, each page by one thread.
    #[must_use]
    pub fn page_order(&self) -> Vec<(String, NodeId)> {
        let mut files: Vec<(String, NodeId)> = self
            .walk()
            .filter(|&(_, id)| !self.node(id).is_dir())
            .collect();
        files.sort_by_key(|&(_, id)| match &self.node(id).kind {
            Kind::File(blocks) => blocks.first().map(|b| (b.page, b.offset)),
            _ => None,
        });
        files
    }

    /// The value the fsindex records for an archive-wide metadata `key`.
    #[must_use]
    pub fn metadata(&self, key: &str) -> Option<&[u8]> {
        self.index
            .metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    /// Every metadata key and its value, in the order the archive first wrote them.
    pub fn metadata_entries(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.index
            .metadata
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    /// The filesets the archive holds, sorted, or none when it was not written with filesets.
    ///
    /// A fileset archive keeps one directory per fileset at its root and names
    /// how one is chosen under the `cookfs.fileset` metadata key.
    #[must_use]
    pub fn filesets(&self) -> Vec<&str> {
        if self.metadata(FILESET_KEY).is_none() {
            return Vec::new();
        }
        match &self.index.nodes[self.index.root].kind {
            Kind::Dir(children) => children
                .iter()
                .map(|&c| &self.index.nodes[c])
                .filter(|n| n.is_dir())
                .map(|n| n.name.as_str())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The fileset [`Self::walk`] lists, if the archive has filesets.
    ///
    /// Upstream picks one by its own Tcl version and platform unless the
    /// archive names a custom fileset, when it takes the first written. With
    /// no Tcl runtime to match, this reader always starts at the first written;
    /// [`Self::select_fileset`] picks another.
    #[must_use]
    pub fn fileset(&self) -> Option<&str> {
        self.fileset.map(|idx| self.index.nodes[idx].name.as_str())
    }

    /// Makes the fileset `name` the one [`Self::walk`] lists.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoSuchFileset`] unless `name` is one of [`Self::filesets`].
    pub fn select_fileset(&mut self, name: &str) -> Result<()> {
        let found = match &self.index.nodes[self.index.root].kind {
            Kind::Dir(children) => children.iter().copied().find(|&c| {
                let node = &self.index.nodes[c];
                node.is_dir() && node.name == name
            }),
            _ => None,
        };
        self.fileset = Some(
            found
                .filter(|_| self.metadata(FILESET_KEY).is_some())
                .context(ctx::NoSuchFileset {
                    name: name.to_owned(),
                })?,
        );
        Ok(())
    }
}

/// The metadata key a fileset archive records how its fileset is chosen under.
const FILESET_KEY: &str = "cookfs.fileset";

/// The fileset upstream activates when it cannot match one to its runtime: the first root entry written.
fn default_fileset(index: &Index) -> Option<NodeId> {
    let has_filesets = index.metadata.iter().any(|(k, _)| k == FILESET_KEY);
    index
        .first_at_root
        .filter(|&idx| has_filesets && index.nodes[idx].is_dir())
}

/// Full opens tried on candidates that pass the cheap check, before the rightmost one's error is reported.
const MAX_OPEN_ATTEMPTS: usize = 8;

/// Reads the trailer behind the signature at `sig_at` and the tree its fsindex holds.
fn assemble<R: ReadAt>(
    src: &R,
    sig_at: u64,
    which: usize,
    opts: &OpenOptions,
) -> Result<Assembled> {
    let limits = &opts.limits;
    let (layout, version, key) = if which == 0 {
        (cfs0002::parse(src, sig_at)?, ArchiveVersion::Cfs0002, None)
    } else {
        let suffix = cfs0003::Suffix::read(src, sig_at)?;
        // Before the pgindex, which `KEY_INDEX` encrypts too.
        let key = archive_key(src, sig_at, &suffix, opts)?;
        let layout = cfs0003::parse(src, sig_at, &suffix, limits, opts.verify, key.as_ref())?;
        (layout, ArchiveVersion::Cfs0003, key)
    };

    let blob = layout.fsindex;
    let raw = source::at(src, blob.at, blob.len as usize)?;
    let plain = blob
        .decode(&raw, limits.max_fsindex_len, opts.verify, key.as_ref())
        .context(ctx::Decode {
            blob: Blob::Fsindex,
        })?;
    let index = Index::parse(&plain, limits.max_depth)?;
    check_blocks(&index, layout.pages.len())?;
    Ok(Assembled {
        layout,
        version,
        index,
        key,
    })
}

/// Everything one trailer candidate opens to.
struct Assembled {
    layout: parsers::Layout,
    version: ArchiveVersion,
    index: Index,
    key: Option<Key>,
}

/// The key an encrypted `CFS0003` archive's blobs decrypt with, from the data after its signature.
fn archive_key<R: ReadAt>(
    src: &R,
    sig_at: u64,
    suffix: &cfs0003::Suffix,
    opts: &OpenOptions,
) -> Result<Option<Key>> {
    let Encryption { mode, level } = suffix.encryption();
    if mode == EncryptionMode::NONE {
        return Ok(None);
    }
    let password = opts.password.as_deref().context(ctx::Encrypted { mode })?;
    let wrapped = mode == EncryptionMode::KEY || mode == EncryptionMode::KEY_INDEX;
    let data_len = crypto::BLOCK
        + if wrapped {
            crypto::BLOCK + crypto::WRAPPED_KEY_LEN
        } else {
            0
        };
    let data = source::at(src, sig_at + cfs0003::SIGNATURE.len() as u64, data_len)
        .context(parsers::trailer_error::Read)?;
    let (salt, rest) = data
        .split_first_chunk::<{ crypto::BLOCK }>()
        .context(ctx::Encrypted { mode })?;
    let derived = Key::derive(password, salt, level);
    if !wrapped {
        return Ok(Some(derived));
    }
    let (iv, stored) = rest
        .split_first_chunk::<{ crypto::BLOCK }>()
        .context(ctx::Encrypted { mode })?;
    let stored: &[u8; crypto::WRAPPED_KEY_LEN] =
        stored.try_into().ok().context(ctx::Encrypted { mode })?;
    derived
        .unwrap(iv, stored)
        .context(ctx::WrongPassword)
        .map(Some)
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

    mod hostile;

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
        let page = (stored(payload), cfs0002::tests::crc_slot(payload));
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
        let (path, idx) = archive.walk().next().unwrap();
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
        let (_, idx) = archive.walk().next().unwrap();
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
        let page = (
            stored(b"0123456789"),
            cfs0002::tests::crc_slot(b"0123456789"),
        );
        let archive = open(cfs0002::tests::archive(&[page], &stored(&fsindex))).unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(let Err(Error::BlockOutOfPage { page: 0, page_len: 10, .. }) = archive.read(idx));
    }

    /// Opens `buf` and reads every file, discarding the outcome; only a panic fails.
    fn exercise(buf: Vec<u8>) {
        let opts = OpenOptions {
            limits: Limits {
                max_fsindex_len: 1 << 16,
                max_page_len: 1 << 16,
                max_file_len: 1 << 20,
                max_depth: 16,
            },
            ..OpenOptions::default()
        };
        if let Ok(archive) = Archive::open(buf, &opts) {
            for (_, idx) in archive.walk() {
                let _ = archive.read(idx);
            }
        }
    }

    mod robustness {
        use super::*;
        use proptest::prelude::*;

        fn mutated(base: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
            let len = base.len();
            proptest::collection::vec((0..len, any::<u8>()), 1..8).prop_map(move |edits| {
                let mut buf = base.clone();
                for (at, byte) in edits {
                    buf[at] = byte;
                }
                buf
            })
        }

        proptest! {
            #[test]
            fn arbitrary_bytes_never_panic(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
                exercise(buf);
            }

            #[test]
            fn a_corrupted_cfs0002_archive_never_panics(buf in mutated(one_file_v2(b"hello world!"))) {
                exercise(buf);
            }

            #[test]
            fn a_corrupted_cfs0003_archive_never_panics(buf in mutated(one_file_v3(b"hello v3!"))) {
                exercise(buf);
            }
        }
    }

    /// Found by the `archive` fuzz target: blocks summing to 4 GiB reserved that much up front.
    #[test]
    fn a_file_claiming_gigabytes_is_refused_before_reading() {
        let fsindex = Fsindex::new(1)
            .file("f", &[(0, 0, i32::MAX), (0, 0, i32::MAX)])
            .finish();
        let page = (
            stored(b"0123456789"),
            cfs0002::tests::crc_slot(b"0123456789"),
        );
        let archive = open(cfs0002::tests::archive(&[page], &stored(&fsindex))).unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(let Err(Error::FileTooLarge { size: 4_294_967_294, .. }) = archive.read(idx));
    }

    /// Many blocks over one page multiply the output without growing the archive.
    #[test]
    fn blocks_repeating_one_page_cannot_pass_the_file_limit() {
        let blocks = vec![(0, 0, 1000); 2000];
        let fsindex = Fsindex::new(1).file("f", &blocks).finish();
        let page = (stored(&[7; 1000]), cfs0002::tests::crc_slot(&[7; 1000]));
        let buf = cfs0002::tests::archive(&[page], &stored(&fsindex));
        let limits = Limits {
            max_file_len: 1 << 20,
            ..Limits::default()
        };
        let archive = Archive::open(
            buf,
            &OpenOptions {
                limits,
                ..OpenOptions::default()
            },
        )
        .unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(let Err(Error::FileTooLarge { size: 2_000_000, .. }) = archive.read(idx));
    }

    /// Blocks cycling through pages force a decode each; the read stops instead of thrashing.
    #[test]
    fn blocks_cycling_through_pages_stop_the_read() {
        let blocks: Vec<_> = (0..30).map(|i| (i % 3, 0, 1)).collect();
        let fsindex = Fsindex::new(1).file("f", &blocks).finish();
        let page = |b| (stored(&[b; 1000]), cfs0002::tests::crc_slot(&[b; 1000]));
        let buf = cfs0002::tests::archive(&[page(1), page(2), page(3)], &stored(&fsindex));
        let limits = Limits {
            max_page_len: 1000,
            ..Limits::default()
        };
        let archive = Archive::open(
            buf,
            &OpenOptions {
                limits,
                ..OpenOptions::default()
            },
        )
        .unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(let Err(Error::Overdecoded { size: 30, decoded: 3000 }) = archive.read(idx));
    }

    #[test]
    fn a_file_revisiting_a_page_in_order_reads() {
        let fsindex = Fsindex::new(1)
            .file("f", &[(0, 0, 2), (1, 0, 2), (0, 2, 2)])
            .finish();
        let pages = [
            (stored(b"abcd"), cfs0002::tests::crc_slot(b"abcd")),
            (stored(b"wxyz"), cfs0002::tests::crc_slot(b"wxyz")),
        ];
        let archive = open(cfs0002::tests::archive(&pages, &stored(&fsindex))).unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(archive.read(idx).unwrap() == b"abwxcd");
    }

    /// `KEY_INDEX` encrypts the pgindex, so the mode is checked before decoding it.
    #[test]
    fn a_key_index_archive_is_refused_as_encrypted_not_as_corrupt() {
        let fsindex = Fsindex::new(1).file("f", &[(0, 0, 1)]).finish();
        let mut buf = cfs0003::tests::archive(&[vec![1]], &fsindex, 0x7B);
        let pgindex_codec = buf.len() - cfs0003::SIGNATURE.len() - 55 + 3;
        buf[pgindex_codec] = Compression::ZLIB.raw();
        check!(let Err(Error::Encrypted { mode: EncryptionMode::KEY_INDEX }) = open(buf));
    }

    /// A page the pgindex flags as encrypted is never handed back as plaintext.
    #[test]
    fn a_page_flagged_encrypted_is_refused() {
        let fsindex = Fsindex::new(1).file("f", &[(0, 0, 3)]).finish();
        let mut buf = cfs0003::tests::archive(&[b"abc".to_vec()], &fsindex, 0x78);
        buf[3 + 4 + 2] = 1;
        let archive = open(buf).unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(let Err(Error::EncryptedPage { page: 0 }) = archive.read(idx));
    }

    /// A stored page whose bytes changed after its `crc32` slot was written.
    #[test]
    fn a_page_failing_its_hash_is_refused_unless_verification_is_off() {
        let fsindex = Fsindex::new(1).file("f", &[(0, 0, 5)]).finish();
        let page = (stored(b"hellp"), cfs0002::tests::crc_slot(b"hello"));
        let buf = cfs0002::tests::archive(&[page], &stored(&fsindex));

        let archive = open(buf.clone()).unwrap();
        let (_, idx) = archive.walk().next().unwrap();
        check!(let Err(Error::Decode { blob: Blob::Page(0), source: DecodeError::HashMismatch { hash: "CRC-32" } }) = archive.read(idx));

        let lax = OpenOptions {
            verify: false,
            ..OpenOptions::default()
        };
        let archive = Archive::open(buf, &lax).unwrap();
        check!(archive.read(idx).unwrap() == b"hellp");
    }

    /// Flipping one byte of every page or index blob in a real archive is caught by its MD5.
    #[test]
    fn a_corrupted_byte_in_an_upstream_archive_fails_its_md5() {
        // Pages start after upstream's 15-byte `CFSS003` stamp, which no hash covers.
        const STAMP: usize = 15;
        let fixture =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3-none.cfs");
        let clean = std::fs::read(fixture).unwrap();
        let read_all = |buf: Vec<u8>| -> Result<()> {
            let archive = open(buf)?;
            for (_, idx) in archive.page_order() {
                archive.read(idx)?;
            }
            Ok(())
        };
        check!(read_all(clean.clone()).is_ok());
        let tail = clean.len() - cfs0003::SIGNATURE.len() - 55;
        let mut caught = 0;
        for at in (STAMP..tail).step_by(97) {
            let mut buf = clean.clone();
            buf[at] ^= 0x01;
            caught += usize::from(read_all(buf).is_err());
        }
        check!(caught == (tail - STAMP).div_ceil(97));
    }

    /// Two filesets at the root; the first written is active, as upstream activates a custom one.
    fn two_filesets() -> Archive<Vec<u8>> {
        let fsindex = Fsindex::new(2)
            .dir("zeta", 1)
            .file("z.txt", &[(0, 0, 1)])
            .dir("alpha", 1)
            .file("a.txt", &[(0, 1, 1)])
            .finish_with(&[b"cookfs.fileset\0custom"]);
        let buf = cfs0003::tests::archive(&[b"za".to_vec()], &fsindex, 0x78);
        open(buf).unwrap()
    }

    #[test]
    fn a_fileset_archive_lists_the_first_written_fileset_as_its_root() {
        let archive = two_filesets();
        check!(archive.filesets() == ["alpha", "zeta"]);
        check!(archive.fileset() == Some("zeta"));
        let walked: Vec<String> = archive.walk().map(|(p, _)| p).collect();
        check!(walked == ["z.txt"]);
        check!(archive.metadata("cookfs.fileset") == Some(&b"custom"[..]));
    }

    #[test]
    fn another_fileset_can_be_selected_and_a_missing_one_is_refused() {
        let mut archive = two_filesets();
        archive.select_fileset("alpha").unwrap();
        let (path, idx) = archive.walk().next().unwrap();
        check!(path == "a.txt");
        check!(archive.read(idx).unwrap() == b"a");
        check!(let Err(Error::NoSuchFileset { .. }) = archive.select_fileset("beta"));
        check!(archive.fileset() == Some("alpha"));
    }

    #[test]
    fn without_fileset_metadata_root_directories_are_plain_directories() {
        let fsindex = Fsindex::new(1).dir("alpha", 0).finish();
        let archive = open(cfs0003::tests::archive(&[], &fsindex, 0x78)).unwrap();
        check!(archive.filesets().is_empty());
        check!(archive.fileset().is_none());
    }

    fn fixture(name: &str) -> Archive<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        open(std::fs::read(path).unwrap()).unwrap()
    }

    /// Streaming must agree with a whole read, in one go or in pieces that straddle blocks and pages.
    #[rstest::rstest]
    #[case::cfs0002("v2-zlib-md5.cfs")]
    #[case::cfs0003("v3-zstd.cfs")]
    fn a_stream_reads_what_read_returns(#[case] name: &str) {
        use std::io::Read;
        let archive = fixture(name);
        for (path, id) in archive.page_order() {
            let whole = archive.read(id).unwrap();
            let mut streamed = Vec::new();
            archive
                .open_file(id)
                .unwrap()
                .read_to_end(&mut streamed)
                .unwrap();
            check!(streamed == whole, "{path}");

            let mut reader = archive.open_file(id).unwrap();
            let mut pieces = Vec::new();
            let mut buf = [0u8; 999];
            loop {
                let n = reader.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                pieces.extend_from_slice(&buf[..n]);
            }
            check!(pieces == whole, "{path}");
        }
    }

    #[test]
    fn a_stream_seeks_anywhere_in_its_file() {
        use std::io::{Read, Seek, SeekFrom};
        let archive = fixture("v3-zlib.cfs");
        let id = archive.lookup("data/random.bin").unwrap();
        let whole = archive.read(id).unwrap();
        let mut reader = archive.open_file(id).unwrap();
        check!(reader.len() == whole.len() as u64);

        for at in [0, 1, 4095, 4096, 4097, 12_345, whole.len() - 1] {
            reader.seek(SeekFrom::Start(at as u64)).unwrap();
            let mut tail = Vec::new();
            reader.read_to_end(&mut tail).unwrap();
            check!(tail == whole[at..], "from {at}");
        }
        check!(reader.seek(SeekFrom::End(-3)).unwrap() == whole.len() as u64 - 3);
        check!(reader.seek(SeekFrom::Current(10)).unwrap() == whole.len() as u64 + 7);
        check!(reader.read(&mut [0; 8]).unwrap() == 0);
        check!(
            reader
                .seek(SeekFrom::Current(-(whole.len() as i64) - 8))
                .is_err()
        );
    }

    #[test]
    fn lookup_follows_names_and_finds_nothing_for_a_missing_one() {
        let archive = fixture("v3-zlib.cfs");
        check!(archive.lookup("") == Some(archive.root()));
        let deep = archive.lookup("nested/a/b/c/deep.txt").unwrap();
        check!(archive.read(deep).unwrap() == b"deep\n");
        check!(archive.node(archive.lookup("nested/a").unwrap()).is_dir());
        for missing in ["nested/z", "nested//a", "readme.txt/x", "/readme.txt"] {
            check!(archive.lookup(missing).is_none(), "{missing}");
        }
    }

    #[test]
    fn page_order_follows_the_data_not_the_names() {
        let archive = fixture("v3-zlib.cfs");
        let starts: Vec<_> = archive
            .page_order()
            .into_iter()
            .filter_map(|(_, id)| match &archive.node(id).kind {
                Kind::File(blocks) => blocks.first().map(|b| (b.page, b.offset)),
                _ => None,
            })
            .collect();
        check!(starts.windows(2).all(|w| w[0] <= w[1]));
        check!(
            archive.page_order().len()
                == archive
                    .walk()
                    .filter(|&(_, id)| !archive.node(id).is_dir())
                    .count()
        );
    }

    #[test]
    fn reading_a_directory_is_an_error() {
        let archive = fixture("v3-zlib.cfs");
        let dir = archive.lookup("data").unwrap();
        check!(let Err(Error::NotAFile) = archive.read(dir));
        check!(let Err(Error::NotAFile) = archive.open_file(dir));
    }

    #[test]
    fn names_that_could_escape_a_directory_are_not_portable() {
        let fsindex = Fsindex::new(6)
            .file("ok.txt", &[])
            .file("..", &[])
            .file(".", &[])
            .file("a/b", &[])
            .file("back\\slash", &[])
            .file("", &[])
            .finish();
        let archive = open(cfs0003::tests::archive(&[], &fsindex, 0x78)).unwrap();
        let portable: Vec<String> = archive
            .walk()
            .filter(|&(_, id)| archive.node(id).has_portable_name())
            .map(|(path, _)| path)
            .collect();
        check!(portable == ["ok.txt"]);

        let fsindex = Fsindex::new(1).dir("..", 1).file("inner", &[]).finish();
        let archive = open(cfs0003::tests::archive(&[], &fsindex, 0x78)).unwrap();
        let inner = archive.lookup("../inner").unwrap();
        check!(archive.node(inner).has_portable_name());
        check!(!archive.has_portable_path(inner));
    }

    /// A stray all-zero trailer before a damaged archive once opened as an empty one.
    #[test]
    fn a_decoy_trailer_does_not_stand_in_for_a_damaged_archive() {
        let mut buf = vec![0u8; 9];
        buf.extend_from_slice(cfs0002::SIGNATURE);
        let mut real = one_file_v2(b"hello");
        let count_at = real.len() - cfs0002::SIGNATURE.len() - 5;
        real[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        buf.extend(real);
        check!(let Err(Error::Trailer { source: TrailerError::NoSignature }) = open(buf));
    }

    /// Every hit used to run a full parse, so a file packed with signatures took hours to refuse.
    #[test]
    fn a_source_packed_with_signatures_is_refused_quickly() {
        let mut unit = [0u8; 16];
        unit[4..8].copy_from_slice(&1000u32.to_be_bytes());
        unit[9..].copy_from_slice(cfs0002::SIGNATURE);
        let buf = unit.repeat(1 << 18);
        let started = std::time::Instant::now();
        check!(open(buf).is_err());
        check!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn an_fsindex_over_the_limit_is_refused() {
        let opts = OpenOptions {
            limits: Limits {
                max_fsindex_len: 4,
                ..Limits::default()
            },
            ..OpenOptions::default()
        };
        let check = Archive::open(one_file_v2(b"x"), &opts);
        check!(let Err(Error::Decode { blob: Blob::Fsindex, source: DecodeError::TooLarge { limit: 4, .. } }) = check);
    }
}
