//! The opened archive and everything that reads through it.

mod fileset;
mod open;

use positioned_io::{ReadAt, Size};
use snafu::{OptionExt, ResultExt, ensure};

use crate::blob::BlobRef;
use crate::cache::{Page, PageCache};
use crate::crypto::{Encryption, Key};
use crate::error::{Blob, Result, error as ctx};
use crate::file::FileReader;
use crate::index::{Index, Kind, Node, NodeId, Walk};
use crate::limits::Limits;
use crate::source;

#[cfg(doc)]
use crate::Error;

pub use open::OpenOptions;

/// The most [`Archive::read`] reserves at once ahead of the bytes it has copied.
const READ_RESERVE_STEP: usize = 64 << 20;

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
    fileset: Option<NodeId>,
}

impl<R: ReadAt + Size> Archive<R> {
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

    /// The largest decoded page the archive may hold, which [`Limits::max_page_len`] sets.
    pub(crate) const fn max_page_len(&self) -> usize {
        self.limits.max_page_len
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
}
