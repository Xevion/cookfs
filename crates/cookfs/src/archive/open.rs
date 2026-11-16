//! Opening an archive: finding its trailer, then assembling its page table and tree.

use positioned_io::{ReadAt, Size};
use snafu::{OptionExt, ResultExt};

use super::{Archive, ArchiveVersion};
use crate::cache::{Budget, PageCache};
use crate::crypto::Key;
use crate::error::{Blob, Result, error as ctx};
use crate::index::{Index, Kind};
use crate::limits::Limits;
use crate::parsers::{self, cfs0002, cfs0003};
use crate::source;

#[cfg(doc)]
use crate::Error;

/// Worker count assumed when the OS cannot report available parallelism.
const WORKERS_FALLBACK: usize = 4;

/// Full opens tried on candidates that pass the cheap check, before the rightmost one's error is reported.
const MAX_OPEN_ATTEMPTS: usize = 8;

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

impl<R: ReadAt + Size> Archive<R> {
    /// Opens a `CFS0002` or `CFS0003` archive found anywhere in `src`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Trailer`] when no signature parses as a trailer,
    /// [`Error::Encrypted`] for an encrypted `CFS0003` archive, and any error
    /// reading the trailer, decoding the fsindex or parsing its tree.
    pub fn open(src: R, opts: &OpenOptions) -> Result<Self> {
        let len = src
            .size()
            .ok()
            .flatten()
            .context(source::source_error::NoLength)?;
        let Assembled {
            layout,
            version,
            index,
            key,
        } = scan(&src, len, opts)?;

        let sizes: Vec<u32> = layout
            .pages
            .iter()
            .map(|p| p.declared.unwrap_or(p.len))
            .collect();
        let workers = std::thread::available_parallelism()
            .map_or(WORKERS_FALLBACK, std::num::NonZeroUsize::get);

        let fileset = super::fileset::default_fileset(&index);
        Ok(Self {
            src,
            version,
            pages: layout.pages,
            index,
            cache: PageCache::new(Budget::from_pages(&sizes, workers)),
            limits: opts.limits,
            verify: opts.verify,
            encryption: layout.encryption,
            key,
            fileset,
        })
    }
}

/// Everything one trailer candidate opens to.
struct Assembled {
    layout: parsers::Layout,
    version: ArchiveVersion,
    index: Index,
    key: Option<Key>,
}

/// Scans `src` backward for a trailer and opens the rightmost candidate that assembles.
///
/// A candidate that passes the cheap check but fails to open may be a decoy
/// after the real archive, so the scan goes on, a bounded number of times.
fn scan<R: ReadAt>(src: &R, len: u64, opts: &OpenOptions) -> Result<Assembled> {
    let mut attempts = 0;
    let mut first_error = None;
    let mut opened = None;
    source::find_signature(
        src,
        len,
        &[cfs0002::SIGNATURE, cfs0003::SIGNATURE],
        |at, which| {
            if !is_plausible(src, at, which) || attempts == MAX_OPEN_ATTEMPTS {
                return false;
            }
            attempts += 1;
            match assemble(src, at, which, opts) {
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
    match (opened, first_error) {
        (Some(found), _) => Ok(found),
        (None, Some(e)) => Err(e),
        (None, None) => parsers::trailer_error::NoSignature.fail()?,
    }
}

/// Whether the signature at `at`, the `which`th of the two formats', has a trailer worth a full open.
fn is_plausible<R: ReadAt>(src: &R, at: u64, which: usize) -> bool {
    if which == 0 {
        cfs0002::plausible(src, at)
    } else {
        cfs0003::Suffix::read(src, at).is_ok_and(|s| s.plausible(at))
    }
}

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
        let key = cfs0003::archive_key(src, sig_at, &suffix, opts.password.as_deref())?;
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
