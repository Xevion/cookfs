//! A reader for cookfs, the page-based Tcl virtual filesystem archive.
//!
//! cookfs ships in two structurally different formats sharing one directory
//! tree encoding: `CFS0002`, the frozen legacy format InstallBuilder
//! installers carry, and `CFS0003`, what upstream writes since 2024. Both
//! are read transparently.

mod bytes;
mod cache;
mod codec;
mod crypto;
mod error;
mod index;
mod limits;
mod name;
mod page;
mod parsers;
mod source;
mod wire;

use positioned_io::{ReadAt, Size};
use snafu::{OptionExt, ResultExt, ensure};

use cache::{Budget, Page, PageCache};
use crypto::Key;
use error::error as ctx;
use index::Index;
use page::BlobRef;
use parsers::{cfs0002, cfs0003};

pub use bytes::BytesError;
pub use codec::CodecError;
pub use error::{Blob, Error, Result};
pub use index::{Block, Idx, IndexError, Kind, Node};
pub use limits::Limits;
pub use parsers::TrailerError;
pub use parsers::cfs0003::{Encryption, EncryptionMode};
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
    ) -> Result<Vec<u8>, crate::CodecError> {
        let expect = crate::codec::Expect { declared, limit };
        crate::codec::decode(crate::wire::Compression::from_raw(id), body, expect)
    }
}

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
    limits: Limits,
    verify: bool,
    encryption: Option<Encryption>,
    key: Option<Key>,
    /// The fileset directory standing in for the root, when the archive has filesets.
    fileset: Option<Idx<Node>>,
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

    fn page(&self, n: u32) -> Result<Page> {
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

    /// Reads a file's full contents, or nothing for a directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FileTooLarge`] past [`Limits::max_file_len`],
    /// [`Error::Decode`] when a page the file spans fails to decode,
    /// [`Error::BlockOutOfPage`] when one of its blocks runs past its page, and
    /// [`Error::Overdecoded`] when its blocks revisit pages far more than a
    /// file written in order does.
    pub fn read(&self, node: Idx<Node>) -> Result<Vec<u8>> {
        let Kind::File(blocks) = &self.index.nodes[node].kind else {
            return Ok(Vec::new());
        };
        let size = self.index.nodes[node].size();
        let limit = self.limits.max_file_len;
        ensure!(size <= limit, ctx::FileTooLarge { size, limit });
        // An in-order file wastes at most the parts of its first and last pages it does not use.
        let budget = size.saturating_add(2 * self.limits.max_page_len as u64);

        // Grown by what pages really return, not reserved from sizes the fsindex claims.
        let mut out = Vec::new();
        let mut decoded = 0u64;
        let mut current: Option<(u32, Page)> = None;
        for &Block {
            page,
            offset,
            size: len,
        } in blocks
        {
            let data = match &current {
                Some((held, data)) if *held == page => data.clone(),
                _ => {
                    let data = self.page(page)?;
                    decoded += data.len() as u64;
                    ensure!(decoded <= budget, ctx::Overdecoded { size, decoded });
                    current = Some((page, data.clone()));
                    data
                }
            };
            let range = offset as usize..offset as usize + len as usize;
            let bytes = data.get(range).context(ctx::BlockOutOfPage {
                page,
                offset,
                size: len,
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
    ///
    /// Paths are relative to the active fileset when the archive has one.
    pub fn walk(&self) -> Vec<(String, Idx<Node>)> {
        self.index.walk(self.fileset.unwrap_or(self.index.root))
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
fn default_fileset(index: &Index) -> Option<Idx<Node>> {
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
    layout: page::Layout,
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
        let page = (
            stored(b"0123456789"),
            cfs0002::tests::crc_slot(b"0123456789"),
        );
        let archive = open(cfs0002::tests::archive(&[page], &stored(&fsindex))).unwrap();
        let (_, idx) = archive.walk().into_iter().next().unwrap();
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
        let (_, idx) = archive.walk().into_iter().next().unwrap();
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
        let (_, idx) = archive.walk().into_iter().next().unwrap();
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
        let (_, idx) = archive.walk().into_iter().next().unwrap();
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
        let (_, idx) = archive.walk().into_iter().next().unwrap();
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
        let (_, idx) = archive.walk().into_iter().next().unwrap();
        check!(let Err(Error::EncryptedPage { page: 0 }) = archive.read(idx));
    }

    /// A stored page whose bytes changed after its `crc32` slot was written.
    #[test]
    fn a_page_failing_its_hash_is_refused_unless_verification_is_off() {
        let fsindex = Fsindex::new(1).file("f", &[(0, 0, 5)]).finish();
        let page = (stored(b"hellp"), cfs0002::tests::crc_slot(b"hello"));
        let buf = cfs0002::tests::archive(&[page], &stored(&fsindex));

        let archive = open(buf.clone()).unwrap();
        let (_, idx) = archive.walk().into_iter().next().unwrap();
        check!(let Err(Error::Decode { blob: Blob::Page(0), source: CodecError::HashMismatch { hash: "CRC-32" } }) = archive.read(idx));

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
            for (_, idx) in archive.walk() {
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
        let walked: Vec<String> = archive.walk().into_iter().map(|(p, _)| p).collect();
        check!(walked == ["z.txt"]);
        check!(archive.metadata("cookfs.fileset") == Some(&b"custom"[..]));
    }

    #[test]
    fn another_fileset_can_be_selected_and_a_missing_one_is_refused() {
        let mut archive = two_filesets();
        archive.select_fileset("alpha").unwrap();
        let (path, idx) = archive.walk().into_iter().next().unwrap();
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
        check!(let Err(Error::Decode { blob: Blob::Fsindex, source: CodecError::TooLarge { limit: 4, .. } }) = check);
    }
}
