//! The fsindex: the directory tree inside a decoded fsindex blob.
//!
//! A directory's children are inlined depth-first, straight after the entry
//! that owns them, so the tree is read in one linear pass. The pass keeps its
//! own stack of open directories rather than recursing, so a deep tree cannot
//! overflow the thread's stack.
//!
//! ```text
//! "CFS2.200"
//! u32 root child count
//! entry*:   u8 name_len, name, NUL, i64 mtime, i32 block_count
//!           block_count == -1: u32 child_count, then the children
//!           otherwise:         block_count * (i32 page, i32 offset, i32 size)
//! u32 metadata count, then per record: u32 len, len bytes (absent in old archives)
//! ```
//!
//! A name repeated within one directory keeps its last entry, as upstream's
//! import does, provided both are files or both directories.

use la_arena::Arena;
pub use la_arena::Idx;
use snafu::{ResultExt, Snafu, ensure};
use zerocopy::byteorder::big_endian::{I32, I64, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::bytes::{BytesError, Reader};

/// The magic that opens every decoded fsindex, in both formats.
pub(crate) const MAGIC: &[u8; 8] = b"CFS2.200";

/// A decoded fsindex that does not describe a valid tree.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum IndexError {
    /// The blob does not open with `CFS2.200`.
    #[snafu(display("fsindex magic is {found:02x?}, not CFS2.200"))]
    BadMagic {
        /// The first bytes of the blob, zero-padded when it is shorter.
        found: [u8; 8],
    },
    /// A record ran past the end of the blob.
    #[snafu(display("fsindex record is truncated"))]
    Truncated {
        /// Where the read failed.
        source: BytesError,
    },
    /// Directories nest deeper than the configured limit.
    #[snafu(display("fsindex nests directories deeper than {limit}"))]
    TooDeep {
        /// The configured depth limit.
        limit: usize,
    },
    /// A block names a negative page, offset or size.
    #[snafu(display("fsindex block names page {page}, offset {offset}, size {size}"))]
    NegativeBlock {
        /// The page as stored.
        page: i32,
        /// The offset as stored.
        offset: i32,
        /// The size as stored.
        size: i32,
    },
    /// A block count is negative but is not the directory marker.
    #[snafu(display("fsindex entry has block count {count}"))]
    BadBlockCount {
        /// The count as stored.
        count: i32,
    },
    /// One directory holds a file and a directory of the same name.
    #[snafu(display("fsindex holds both a file and a directory named {name:?}"))]
    KindConflict {
        /// The name both entries carry.
        name: String,
    },
    /// Bytes remain after the tree and its metadata.
    #[snafu(display("fsindex has {extra} bytes after its metadata"))]
    Trailing {
        /// How many bytes were left unread.
        extra: usize,
    },
}

const _: () = assert!(size_of::<IndexError>() <= 64);

/// One byte range of a file's contents, inside one decoded page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Block {
    /// Index of the page in the archive's page table.
    pub page: u32,
    /// Offset into the decoded page.
    pub offset: u32,
    /// Length in bytes.
    pub size: u32,
}

/// What a node is: a directory of children, or a file's blocks.
#[derive(Debug)]
#[non_exhaustive]
pub enum Kind {
    /// A directory, holding its children sorted by name.
    Dir(Vec<Idx<Node>>),
    /// A file, holding the blocks that make up its contents in order.
    File(Vec<Block>),
}

/// One entry in the tree.
#[derive(Debug)]
#[non_exhaustive]
pub struct Node {
    /// The entry's own name, not its path.
    pub name: String,
    /// Modification time as the writing Tcl runtime recorded it.
    pub mtime: i64,
    /// The parent directory, or `None` for the root.
    pub parent: Option<Idx<Self>>,
    /// Directory or file, with its payload.
    pub kind: Kind,
}

impl Node {
    /// Whether this entry is a directory.
    #[must_use]
    pub const fn is_dir(&self) -> bool {
        matches!(self.kind, Kind::Dir(_))
    }

    /// Decoded size: the sum of a file's blocks, or 0 for a directory.
    #[must_use]
    pub fn size(&self) -> u64 {
        match &self.kind {
            Kind::File(blocks) => blocks.iter().map(|b| u64::from(b.size)).sum(),
            Kind::Dir(_) => 0,
        }
    }
}

/// The parsed tree of one archive.
#[derive(Debug)]
pub(crate) struct Index {
    pub(crate) nodes: Arena<Node>,
    pub(crate) root: Idx<Node>,
}

/// The fixed fields after an entry's name.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct EntryHead {
    mtime: I64,
    block_count: I32,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawBlock {
    page: I32,
    offset: I32,
    size: I32,
}

const DIR_MARKER: i32 = -1;

/// The smallest entry: a zero-length name, its NUL, and the fixed head.
const MIN_ENTRY_LEN: usize = 1 + 1 + size_of::<EntryHead>();

impl Index {
    /// Parses a decoded fsindex blob into a tree no deeper than `max_depth`.
    pub(crate) fn parse(blob: &[u8], max_depth: usize) -> Result<Self, IndexError> {
        let mut found = [0u8; 8];
        let head = &blob[..blob.len().min(8)];
        found[..head.len()].copy_from_slice(head);
        ensure!(&found == MAGIC, index_error::BadMagic { found });

        let mut r = Reader::new(&blob[MAGIC.len()..]);
        let mut nodes = Arena::new();
        let root = nodes.alloc(Node {
            name: String::new(),
            mtime: 0,
            parent: None,
            kind: Kind::Dir(Vec::new()),
        });

        // Each open directory with the count of its children still unread.
        let mut open = vec![(root, read_child_count(&mut r)?)];
        while let Some((dir, left)) = open.last_mut() {
            if *left == 0 {
                let dir = *dir;
                open.pop();
                settle(&mut nodes, dir)?;
                continue;
            }
            *left -= 1;
            let parent = *dir;

            let len = r.u8().context(index_error::Truncated)?;
            let name = String::from_utf8_lossy(r.take(len.into()).context(index_error::Truncated)?)
                .into_owned();
            r.take(1).context(index_error::Truncated)?; // the name's NUL
            let head = r.record::<EntryHead>().context(index_error::Truncated)?;

            let (kind, children) = match head.block_count.get() {
                DIR_MARKER => {
                    let count = read_child_count(&mut r)?;
                    // Not pre-sized: the count is checked against bytes left, which
                    // every open directory above has already claimed too.
                    (Kind::Dir(Vec::new()), Some(count))
                }
                count @ 0.. => {
                    let raw = r
                        .records::<RawBlock>(count.unsigned_abs())
                        .context(index_error::Truncated)?;
                    (
                        Kind::File(raw.iter().filter_map(block).collect::<Result<_, _>>()?),
                        None,
                    )
                }
                count => return index_error::BadBlockCount { count }.fail(),
            };

            let idx = nodes.alloc(Node {
                name,
                mtime: head.mtime.get(),
                parent: Some(parent),
                kind,
            });
            if let Kind::Dir(siblings) = &mut nodes[parent].kind {
                siblings.push(idx);
            }
            if let Some(count) = children {
                ensure!(
                    open.len() < max_depth,
                    index_error::TooDeep { limit: max_depth }
                );
                open.push((idx, count));
            }
        }

        // Archive-wide key/value records follow the tree; consumed here so a
        // desynchronized parse cannot pass as complete. Archives older than
        // the metadata section end with the tree.
        if r.remaining() == 0 {
            return Ok(Self { nodes, root });
        }
        let count = r.record::<U32>().context(index_error::Truncated)?.get();
        let count = r
            .check_count(count, size_of::<U32>())
            .context(index_error::Truncated)?;
        for _ in 0..count {
            let len = r.record::<U32>().context(index_error::Truncated)?.get();
            r.take(len as usize).context(index_error::Truncated)?;
        }

        ensure!(
            r.remaining() == 0,
            index_error::Trailing {
                extra: r.remaining()
            }
        );
        Ok(Self { nodes, root })
    }

    /// Every node in pre-order, siblings sorted by name, with its full path.
    pub(crate) fn walk(&self) -> Vec<(String, Idx<Node>)> {
        let mut out = Vec::new();
        let mut pending = Vec::new();
        self.queue_children(self.root, "", &mut pending);
        while let Some((idx, path)) = pending.pop() {
            self.queue_children(idx, &path, &mut pending);
            out.push((path, idx));
        }
        out
    }

    /// Pushes a directory's children in reverse, so popping yields them in name order.
    fn queue_children(&self, dir: Idx<Node>, prefix: &str, pending: &mut Vec<(Idx<Node>, String)>) {
        let Kind::Dir(children) = &self.nodes[dir].kind else {
            return;
        };
        pending.extend(children.iter().rev().map(|&child| {
            let name = &self.nodes[child].name;
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            (child, path)
        }));
    }
}

/// Sorts a finished directory's children by name, keeping the last of any repeated name.
///
/// A dropped entry stays in the arena but is no longer reachable from the root.
fn settle(nodes: &mut Arena<Node>, dir: Idx<Node>) -> Result<(), IndexError> {
    let Kind::Dir(children) = &mut nodes[dir].kind else {
        return Ok(());
    };
    let mut children = std::mem::take(children);
    // Stable, so within a run of one name the fsindex order survives and the last entry is last.
    children.sort_by(|&a, &b| nodes[a].name.cmp(&nodes[b].name));
    let mut kept: Vec<Idx<Node>> = Vec::with_capacity(children.len());
    for child in children {
        match kept.last_mut() {
            Some(prev) if nodes[*prev].name == nodes[child].name => {
                ensure!(
                    nodes[*prev].is_dir() == nodes[child].is_dir(),
                    index_error::KindConflict {
                        name: nodes[child].name.clone()
                    }
                );
                *prev = child;
            }
            _ => kept.push(child),
        }
    }
    nodes[dir].kind = Kind::Dir(kept);
    Ok(())
}

fn read_child_count(r: &mut Reader<'_>) -> Result<usize, IndexError> {
    let count = r.record::<U32>().context(index_error::Truncated)?.get();
    r.check_count(count, MIN_ENTRY_LEN)
        .context(index_error::Truncated)
}

/// Converts a stored block, dropping one of zero bytes.
///
/// Upstream writes an empty file as a single block on page -1, and its reader
/// skips a zero-size block without touching the page it names.
fn block(raw: &RawBlock) -> Option<Result<Block, IndexError>> {
    let (page, offset, size) = (raw.page.get(), raw.offset.get(), raw.size.get());
    if size == 0 {
        return None;
    }
    Some(
        match (
            u32::try_from(page),
            u32::try_from(offset),
            u32::try_from(size),
        ) {
            (Ok(page), Ok(offset), Ok(size)) => Ok(Block { page, offset, size }),
            _ => index_error::NegativeBlock { page, offset, size }.fail(),
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert2::{assert, check};

    /// Builds fsindex blobs entry by entry, in the order they appear on disk.
    #[derive(Default)]
    pub(crate) struct Fsindex {
        body: Vec<u8>,
    }

    impl Fsindex {
        pub(crate) fn new(root_children: u32) -> Self {
            let mut body = MAGIC.to_vec();
            body.extend_from_slice(&root_children.to_be_bytes());
            Self { body }
        }

        fn name(&mut self, name: &str) {
            self.body.push(name.len() as u8);
            self.body.extend_from_slice(name.as_bytes());
            self.body.push(0);
            self.body.extend_from_slice(&0i64.to_be_bytes());
        }

        pub(crate) fn file(mut self, name: &str, blocks: &[(i32, i32, i32)]) -> Self {
            self.name(name);
            self.body
                .extend_from_slice(&(blocks.len() as i32).to_be_bytes());
            for &block in blocks {
                let fields: [i32; 3] = block.into();
                for v in fields {
                    self.body.extend_from_slice(&v.to_be_bytes());
                }
            }
            self
        }

        pub(crate) fn dir(mut self, name: &str, children: u32) -> Self {
            self.name(name);
            self.body.extend_from_slice(&DIR_MARKER.to_be_bytes());
            self.body.extend_from_slice(&children.to_be_bytes());
            self
        }

        pub(crate) fn finish(mut self) -> Vec<u8> {
            self.body.extend_from_slice(&0u32.to_be_bytes());
            self.body
        }
    }

    fn paths(index: &Index) -> Vec<String> {
        index.walk().into_iter().map(|(path, _)| path).collect()
    }

    #[test]
    fn an_inlined_subdirectory_resumes_its_parents_list_after_it() {
        let blob = Fsindex::new(2)
            .dir("docs", 1)
            .file("readme.txt", &[(0, 0, 42)])
            .file("z.txt", &[(0, 42, 1)])
            .finish();
        let index = Index::parse(&blob, 8).unwrap();
        check!(paths(&index) == ["docs", "docs/readme.txt", "z.txt"]);
    }

    #[test]
    fn walk_is_pre_order_with_siblings_sorted_by_name() {
        let blob = Fsindex::new(2)
            .dir("b", 1)
            .file("x", &[])
            .dir("a", 0)
            .finish();
        let index = Index::parse(&blob, 8).unwrap();
        check!(paths(&index) == ["a", "b", "b/x"]);
    }

    #[test]
    fn a_file_sums_its_blocks() {
        let blob = Fsindex::new(1).file("f", &[(0, 0, 3), (1, 0, 4)]).finish();
        let index = Index::parse(&blob, 8).unwrap();
        let (_, f) = index.walk()[0].clone();
        check!(index.nodes[f].size() == 7);
    }

    #[test]
    fn a_tree_deeper_than_the_limit_is_refused() {
        let mut fs = Fsindex::new(1);
        for _ in 0..4 {
            fs = fs.dir("d", 1);
        }
        let blob = fs.file("f", &[]).finish();
        check!(let Err(IndexError::TooDeep { limit: 3 }) = Index::parse(&blob, 3));
    }

    #[test]
    fn a_zero_size_block_on_page_minus_one_is_an_empty_file() {
        let blob = Fsindex::new(1).file("empty", &[(-1, 0, 0)]).finish();
        let index = Index::parse(&blob, 8).unwrap();
        let (_, f) = index.walk()[0].clone();
        assert!(let Kind::File(blocks) = &index.nodes[f].kind);
        check!(blocks.is_empty());
    }

    #[test]
    fn a_negative_block_field_is_refused_at_parse() {
        let blob = Fsindex::new(1).file("f", &[(0, -1, 4)]).finish();
        check!(let Err(IndexError::NegativeBlock { offset: -1, .. }) = Index::parse(&blob, 8));
    }

    #[test]
    fn a_child_count_larger_than_the_blob_fails_without_allocating() {
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&u32::MAX.to_be_bytes());
        check!(let Err(IndexError::Truncated { .. }) = Index::parse(&blob, 8));
    }

    #[test]
    fn the_wrong_magic_is_refused() {
        check!(let Err(IndexError::BadMagic { .. }) = Index::parse(b"not the magic", 8));
    }

    #[test]
    fn a_repeated_name_keeps_its_last_entry() {
        let blob = Fsindex::new(3)
            .file("f", &[(0, 0, 1)])
            .file("g", &[])
            .file("f", &[(0, 0, 2)])
            .finish();
        let index = Index::parse(&blob, 8).unwrap();
        let walked = index.walk();
        check!(walked.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>() == ["f", "g"]);
        check!(index.nodes[walked[0].1].size() == 2);
    }

    #[test]
    fn a_repeated_directory_drops_the_earlier_ones_children() {
        let blob = Fsindex::new(2)
            .dir("d", 1)
            .file("old", &[])
            .dir("d", 1)
            .file("new", &[])
            .finish();
        let index = Index::parse(&blob, 8).unwrap();
        check!(paths(&index) == ["d", "d/new"]);
    }

    #[test]
    fn a_file_and_directory_sharing_a_name_are_refused() {
        let blob = Fsindex::new(2).file("x", &[]).dir("x", 0).finish();
        check!(let Err(IndexError::KindConflict { .. }) = Index::parse(&blob, 8));
    }

    #[test]
    fn an_fsindex_ending_after_its_tree_has_no_metadata() {
        let mut blob = Fsindex::new(1).file("f", &[]).finish();
        blob.truncate(blob.len() - 4);
        check!(paths(&Index::parse(&blob, 8).unwrap()) == ["f"]);
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut blob = Fsindex::new(1).file("f", &[]).finish();
        blob.push(0xFF);
        check!(let Err(IndexError::Trailing { extra: 1 }) = Index::parse(&blob, 8));
    }

    #[test]
    fn a_truncated_blob_errors_instead_of_panicking() {
        let mut blob = Fsindex::new(1).file("f", &[(0, 0, 4)]).finish();
        blob.truncate(blob.len() - 5);
        check!(let Err(IndexError::Truncated { .. }) = Index::parse(&blob, 8));
    }
}
