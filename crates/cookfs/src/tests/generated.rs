//! Generated trees packed into archives of both formats, which must read back exactly.

use std::collections::BTreeMap;

use proptest::prelude::*;

use super::kit::{Fsindex, archive_v2, archive_v3, crc_slot, md5_slot, read_all};
use crate::Limits;
use crate::codec::testing::deflate;

/// Wraps `buf` the way an installer does: bytes before it and bytes after it.
fn wrapped(prefix: &[u8], buf: &[u8], suffix: &[u8]) -> Vec<u8> {
    [prefix, buf, suffix].concat()
}

/// Bytes that hold no signature, so they cannot be mistaken for a trailer.
fn junk() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..2048)
        .prop_filter("holds a signature", |b| !b.windows(4).any(|w| w == b"CFS0"))
}

/// A generated tree: each file's path components and contents, keyed so no path repeats.
fn files() -> impl Strategy<Value = BTreeMap<Vec<String>, Vec<u8>>> {
    let dir = prop::sample::select(vec!["d0", "d1", "d 2", "caf\u{e9}"]);
    let leaf = "[a-z\u{e9}\u{65e5} ._-]{1,12}".prop_map(|s| format!("f{s}"));
    let path = (prop::collection::vec(dir, 0..4), leaf).prop_map(|(dirs, leaf)| {
        let mut path: Vec<String> = dirs.into_iter().map(str::to_owned).collect();
        path.push(leaf);
        path
    });
    prop::collection::btree_map(path, prop::collection::vec(any::<u8>(), 0..300), 0..24)
}

/// Every path a tree implies, directories included, mapped to its contents or `None` for a directory.
fn expected(files: &BTreeMap<Vec<String>, Vec<u8>>) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for (path, data) in files {
        for depth in 1..path.len() {
            out.insert(path[..depth].join("/"), None);
        }
        out.insert(path.join("/"), Some(data.clone()));
    }
    out
}

/// A directory of the generated tree, holding subdirectories and files by name.
#[derive(Default)]
struct Dir {
    dirs: BTreeMap<String, Self>,
    files: BTreeMap<String, Vec<(i32, i32, i32)>>,
}

/// Cuts every file, in order, into pages of `page_len` bytes, as upstream's legacy writer does.
fn pack(files: &BTreeMap<Vec<String>, Vec<u8>>, page_len: usize) -> (Vec<Vec<u8>>, Dir) {
    let mut pages: Vec<Vec<u8>> = vec![Vec::new()];
    let mut root = Dir::default();
    for (path, data) in files {
        let mut blocks = Vec::new();
        let mut rest = data.as_slice();
        while !rest.is_empty() {
            if pages.last().unwrap().len() == page_len {
                pages.push(Vec::new());
            }
            let at = pages.len() - 1;
            let page = &mut pages[at];
            let space = page_len - page.len();
            let (piece, tail) = rest.split_at(space.min(rest.len()));
            blocks.push((at as i32, page.len() as i32, piece.len() as i32));
            page.extend_from_slice(piece);
            rest = tail;
        }
        if blocks.is_empty() {
            blocks.push((-1, 0, 0));
        }
        let (leaf, dirs) = path.split_last().unwrap();
        let dir = dirs.iter().fold(&mut root, |dir, name| {
            dir.dirs.entry(name.clone()).or_default()
        });
        dir.files.insert(leaf.clone(), blocks);
    }
    if pages.last().unwrap().is_empty() {
        pages.pop();
    }
    (pages, root)
}

fn emit(fs: Fsindex, dir: &Dir) -> Fsindex {
    let fs = dir.dirs.iter().fold(fs, |fs, (name, sub)| {
        emit(fs.dir(name, (sub.dirs.len() + sub.files.len()) as u32), sub)
    });
    dir.files
        .iter()
        .fold(fs, |fs, (name, blocks)| fs.file(name, blocks))
}

fn fsindex_of(root: &Dir) -> Vec<u8> {
    emit(
        Fsindex::new((root.dirs.len() + root.files.len()) as u32),
        root,
    )
    .finish()
}

/// Builds a `CFS0002` archive, each page stored or deflated and hashed in either mode as `codecs` picks.
fn build_v2(files: &BTreeMap<Vec<String>, Vec<u8>>, page_len: usize, codecs: &[bool]) -> Vec<u8> {
    let (pages, root) = pack(files, page_len);
    let blobs: Vec<(Vec<u8>, [u8; 16])> = pages
        .iter()
        .enumerate()
        .map(|(i, page)| {
            let deflated = codecs[i % codecs.len()];
            let mut blob = vec![u8::from(deflated)];
            blob.extend_from_slice(&if deflated {
                deflate(page)
            } else {
                page.clone()
            });
            let slot = if deflated {
                md5_slot(page)
            } else {
                crc_slot(page)
            };
            (blob, slot)
        })
        .collect();
    let mut index = vec![0u8];
    index.extend_from_slice(&fsindex_of(&root));
    archive_v2(&blobs, &index)
}

fn build_v3(files: &BTreeMap<Vec<String>, Vec<u8>>, page_len: usize) -> Vec<u8> {
    let (pages, root) = pack(files, page_len);
    archive_v3(&pages, &fsindex_of(&root), 0)
}

proptest! {
    #[test]
    fn a_generated_cfs0002_archive_reads_back_every_file(
        files in files(),
        page_len in 1usize..96,
        codecs in prop::collection::vec(any::<bool>(), 1..4),
    ) {
        let got = read_all(build_v2(&files, page_len, &codecs), Limits::default()).unwrap();
        prop_assert_eq!(got, expected(&files));
    }

    #[test]
    fn a_generated_cfs0003_archive_reads_back_every_file(files in files(), page_len in 1usize..96) {
        let got = read_all(build_v3(&files, page_len), Limits::default()).unwrap();
        prop_assert_eq!(got, expected(&files));
    }

    /// The archive is found from its own trailer, whatever bytes surround it.
    #[test]
    fn bytes_around_an_archive_change_nothing_read_from_it(
        files in files(),
        page_len in 1usize..96,
        prefix in junk(),
        suffix in junk(),
        v3 in any::<bool>(),
    ) {
        let buf = if v3 { build_v3(&files, page_len) } else { build_v2(&files, page_len, &[true, false]) };
        let got = read_all(wrapped(&prefix, &buf, &suffix), Limits::default()).unwrap();
        prop_assert_eq!(got, expected(&files));
    }
}
