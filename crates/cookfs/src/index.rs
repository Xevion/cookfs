//! The fsindex: the directory tree stored inside a decompressed fsindex blob.
//!
//! A directory's children are inlined depth-first, immediately after the
//! directory entry that owns them, rather than pointed to by offset. Reading
//! the tree is therefore a single linear pass over the blob.

use la_arena::Arena;
pub use la_arena::Idx;
use snafu::ensure;

use crate::read::{BadMagicSnafu, Cursor, DesyncSnafu, FSINDEX_MAGIC, Result};

/// One compressed byte range that a file's contents span.
#[derive(Debug, Clone, Copy)]
pub struct Block {
    /// Index of the page holding this range, in the archive's page table.
    pub page: i32,
    /// Byte offset into the page's decompressed bytes.
    pub offset: i32,
    /// Length of the range in bytes.
    pub size: i32,
}

/// What a node in the tree is: a directory of children, or a file's blocks.
#[derive(Debug)]
pub enum Kind {
    /// A directory, holding its children in fsindex order.
    Dir(Vec<Idx<Node>>),
    /// A file, holding the blocks that make up its contents.
    File(Vec<Block>),
}

/// One entry in the fsindex tree: a file or a directory.
#[derive(Debug)]
pub struct Node {
    /// The entry's own name, not its full path.
    pub name: String,
    /// Modification time, in whatever epoch the archive's Tcl runtime used.
    pub mtime: i64,
    /// The parent directory, or `None` for the root.
    pub parent: Option<Idx<Self>>,
    /// Whether this entry is a file or a directory, and its payload.
    pub kind: Kind,
}

impl Node {
    /// Whether this entry is a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        matches!(self.kind, Kind::Dir(_))
    }

    /// Decompressed size: the sum of a file's blocks, or 0 for a directory.
    #[must_use]
    pub fn size(&self) -> u64 {
        match &self.kind {
            Kind::File(blocks) => blocks.iter().map(|b| b.size.max(0) as u64).sum(),
            Kind::Dir(_) => 0,
        }
    }
}

/// The parsed directory tree of one archive.
#[derive(Debug)]
pub struct Index {
    /// Arena holding every node keyed by its [`Idx`].
    pub nodes: Arena<Node>,
    /// Handle of the archive's implicit root directory.
    pub root: Idx<Node>,
}

impl Index {
    /// Parses a decompressed fsindex blob into a tree.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::BadMagic`] if the blob does not open with the
    /// expected magic, [`crate::Error::Truncated`] if a truncated or crafted
    /// blob runs out of bytes mid-record, or [`crate::Error::Desync`] if the
    /// parser does not consume exactly the bytes it was given.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        ensure!(
            blob.starts_with(FSINDEX_MAGIC),
            BadMagicSnafu {
                magic: blob[..FSINDEX_MAGIC.len().min(blob.len())].to_vec()
            }
        );

        let mut nodes = Arena::new();
        let root = nodes.alloc(Node {
            name: String::new(),
            mtime: 0,
            parent: None,
            kind: Kind::Dir(Vec::new()),
        });

        let mut cursor = Cursor::new(blob);
        cursor.take(FSINDEX_MAGIC.len())?;
        let children = read_dir(&mut cursor, &mut nodes, root)?;
        nodes[root].kind = Kind::Dir(children);

        // Trailing metadata records (archive-wide key/value pairs) follow the tree.
        // Unused here, but still consumed to prove the blob was read in full.
        let count = cursor.be32()? as usize;
        for _ in 0..count {
            let len = cursor.be32()? as usize;
            cursor.take(len)?;
        }

        ensure!(
            cursor.pos() == blob.len(),
            DesyncSnafu {
                got: cursor.pos(),
                len: blob.len()
            }
        );

        Ok(Self { nodes, root })
    }

    /// Walks the tree depth-first, yielding each node with its full path.
    pub fn walk(&self) -> Vec<(String, Idx<Node>)> {
        let mut out = Vec::new();
        self.walk_into(self.root, "", &mut out);
        out
    }

    fn walk_into(&self, at: Idx<Node>, prefix: &str, out: &mut Vec<(String, Idx<Node>)>) {
        let Kind::Dir(children) = &self.nodes[at].kind else {
            return;
        };
        let mut sorted: Vec<_> = children.clone();
        sorted.sort_by(|&a, &b| self.nodes[a].name.cmp(&self.nodes[b].name));

        for child in sorted {
            let node = &self.nodes[child];
            let path = if prefix.is_empty() {
                node.name.clone()
            } else {
                format!("{prefix}/{}", node.name)
            };
            out.push((path.clone(), child));
            if node.is_dir() {
                self.walk_into(child, &path, out);
            }
        }
    }
}

const DIR_MARKER: i32 = -1;

/// Cap for `Vec::with_capacity` from untrusted count fields; the vector grows
/// naturally past this bound, but a crafted count cannot force a huge
/// pre-allocation before the cursor errors on missing bytes.
const MAX_PREALLOC: usize = 1024;

fn read_dir(
    cursor: &mut Cursor<'_>,
    nodes: &mut Arena<Node>,
    parent: Idx<Node>,
) -> Result<Vec<Idx<Node>>> {
    let count = cursor.be32()? as usize;

    let mut out = Vec::with_capacity(count.min(MAX_PREALLOC));
    for _ in 0..count {
        let nlen = cursor.u8()? as usize;
        let name = String::from_utf8_lossy(cursor.take(nlen)?).into_owned();
        cursor.take(1)?; // trailing NUL

        let mtime = cursor.be64i()?;
        let nblocks = cursor.be32i()?;

        if nblocks == DIR_MARKER {
            let idx = nodes.alloc(Node {
                name,
                mtime,
                parent: Some(parent),
                kind: Kind::Dir(Vec::new()),
            });
            // Subdirectories are inlined here, mid-list, before the parent's
            // next sibling.
            let children = read_dir(cursor, nodes, idx)?;
            nodes[idx].kind = Kind::Dir(children);
            out.push(idx);
        } else {
            let cap = (nblocks.max(0) as usize).min(MAX_PREALLOC);
            let mut blocks = Vec::with_capacity(cap);
            for _ in 0..nblocks {
                blocks.push(Block {
                    page: cursor.be32i()?,
                    offset: cursor.be32i()?,
                    size: cursor.be32i()?,
                });
            }
            out.push(nodes.alloc(Node {
                name,
                mtime,
                parent: Some(parent),
                kind: Kind::File(blocks),
            }));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;

    fn file_entry(name: &str, mtime: i64, blocks: &[Block]) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(&mtime.to_be_bytes());
        out.extend_from_slice(&(blocks.len() as i32).to_be_bytes());
        for b in blocks {
            out.extend_from_slice(&b.page.to_be_bytes());
            out.extend_from_slice(&b.offset.to_be_bytes());
            out.extend_from_slice(&b.size.to_be_bytes());
        }
        out
    }

    fn dir_entry(name: &str, mtime: i64, child_count: u32, children: &[u8]) -> Vec<u8> {
        let mut out = vec![name.len() as u8];
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(&mtime.to_be_bytes());
        out.extend_from_slice(&DIR_MARKER.to_be_bytes());
        out.extend_from_slice(&child_count.to_be_bytes());
        out.extend_from_slice(children);
        out
    }

    /// One directory ("docs") holding one file ("readme.txt"), at the root.
    fn one_dir_one_file_blob() -> Vec<u8> {
        let file = file_entry(
            "readme.txt",
            1_700_000_000,
            &[Block {
                page: 0,
                offset: 0,
                size: 42,
            }],
        );
        let dir = dir_entry("docs", 1_700_000_000, 1, &file);

        let mut blob = FSINDEX_MAGIC.to_vec();
        blob.extend_from_slice(&1u32.to_be_bytes()); // root has one child
        blob.extend_from_slice(&dir);
        blob.extend_from_slice(&0u32.to_be_bytes()); // zero metadata records
        blob
    }

    #[test]
    fn parse_rejects_a_blob_with_the_wrong_magic() {
        check!(let Err(crate::Error::BadMagic { .. }) = Index::parse(b"not the magic bytes"));
    }

    #[test]
    fn parse_reads_one_directory_with_one_file() {
        let blob = one_dir_one_file_blob();
        let index = Index::parse(&blob).unwrap();

        let Kind::Dir(root_children) = &index.nodes[index.root].kind else {
            panic!("root must be a directory");
        };
        check!(root_children.len() == 1);

        let dir = &index.nodes[root_children[0]];
        check!(dir.name == "docs");
        check!(dir.is_dir());

        let Kind::Dir(dir_children) = &dir.kind else {
            panic!("docs must be a directory");
        };
        check!(dir_children.len() == 1);

        let file = &index.nodes[dir_children[0]];
        check!(file.name == "readme.txt");
        check!(!file.is_dir());
        check!(file.size() == 42);
    }

    #[test]
    fn walk_yields_the_full_path_for_every_node() {
        let blob = one_dir_one_file_blob();
        let index = Index::parse(&blob).unwrap();

        let paths: Vec<String> = index.walk().into_iter().map(|(path, _)| path).collect();
        check!(paths == vec!["docs".to_owned(), "docs/readme.txt".to_owned()]);
    }

    #[test]
    fn parse_rejects_a_blob_with_trailing_garbage() {
        let mut blob = one_dir_one_file_blob();
        blob.push(0xFF); // one byte the parser never consumes
        check!(let Err(crate::Error::Desync { .. }) = Index::parse(&blob));
    }

    /// A truncated fsindex must error cleanly, not panic on an out-of-bounds slice.
    #[test]
    fn parse_errors_instead_of_panicking_on_a_truncated_blob() {
        let mut blob = one_dir_one_file_blob();
        blob.truncate(blob.len() - 5);
        check!(let Err(crate::Error::Truncated { .. }) = Index::parse(&blob));
    }
}
