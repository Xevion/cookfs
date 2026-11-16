//! The public reading API against archives upstream wrote.

use assert2::check;
use cookfs::{Archive, Error, Kind, OpenOptions};

use crate::common::fixtures_dir;

fn fixture(name: &str) -> Archive<Vec<u8>> {
    let path = fixtures_dir().join(name);
    let buf = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Archive::open(buf, &OpenOptions::default())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
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
