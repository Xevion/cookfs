//! Ceilings on what an archive's own bytes can make the reader allocate.

/// Bounds on decoded sizes and tree depth, passed to every open.
///
/// Both formats store sizes the reader must trust before it can check them,
/// and `CFS0002` stores none at all for its fsindex or for pages in `md5`
/// hash mode. These ceilings turn a crafted size into an error instead of an
/// allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest decoded fsindex, in bytes.
    pub max_fsindex_len: usize,
    /// Largest decoded page or pgindex, in bytes.
    pub max_page_len: usize,
    /// Deepest directory nesting the fsindex may describe.
    pub max_depth: usize,
}

impl Limits {
    /// 256 MiB, far above any directory tree in the sample corpus.
    pub const DEFAULT_MAX_FSINDEX_LEN: usize = 256 << 20;
    /// 1 GiB. Real pages run from hundreds of KiB to tens of MiB.
    pub const DEFAULT_MAX_PAGE_LEN: usize = 1 << 30;
    /// Deeper than any real install tree, shallow enough to bound the walk.
    pub const DEFAULT_MAX_DEPTH: usize = 512;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_fsindex_len: Self::DEFAULT_MAX_FSINDEX_LEN,
            max_page_len: Self::DEFAULT_MAX_PAGE_LEN,
            max_depth: Self::DEFAULT_MAX_DEPTH,
        }
    }
}
