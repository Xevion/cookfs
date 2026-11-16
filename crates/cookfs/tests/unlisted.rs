//! Archives upstream wrote that a listing cannot describe, each checked against what it holds.

use std::path::Path;

use assert2::check;
use cookfs::{Archive, OpenOptions};

fn open(name: &str) -> cookfs::Result<Archive<Vec<u8>>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("unlisted")
        .join(name);
    let buf = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Archive::open(buf, &OpenOptions::default())
}

/// Both trees write `line\nbreak` and `plain` at the root, the first entry before the second.
#[rstest::rstest]
#[case::legacy("v2-newline-name.cfs")]
#[case::current("v3-newline-name.cfs")]
fn a_name_holding_a_newline_reads_back_whole(#[case] name: &str) {
    let archive = open(name).unwrap();
    let files: Vec<(String, Vec<u8>)> = archive
        .walk()
        .filter(|&(_, idx)| !archive.node(idx).is_dir())
        .filter(|(path, _)| !path.contains('/'))
        .map(|(path, idx)| (path, archive.read(idx).unwrap()))
        .collect();
    check!(
        files
            == [
                ("line\nbreak".to_owned(), b"contents of entry 0\n".to_vec()),
                ("plain".to_owned(), b"contents of entry 1\n".to_vec()),
            ]
    );
}
