//! Bounds on what pages, blocks, the page cache and the trailer scan may hold or cost.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use assert2::{assert, check};

use super::alloc::{live, peak};
use super::kit::{
    Fsindex, MIB, TIME_BOUND, archive_v2, digits_v2, md5_slot, open, open_with, stored,
};
use crate::codec::testing::deflate;
use crate::parsers::cfs0002;
use crate::{Error, Kind, Limits};

/// One deflated page of `len` zeros, behind the `CFS0002` zlib id byte.
fn zero_page(len: usize) -> Vec<u8> {
    let mut blob = vec![1u8];
    blob.extend_from_slice(&deflate(&vec![0; len]));
    blob
}

#[test]
fn the_page_cache_stays_under_its_ceiling_when_pages_declare_no_size() {
    const PAGES: usize = 24;
    const CEILING: usize = 128 * MIB;
    let page = zero_page(8 * MIB);
    let mut fs = Fsindex::new(PAGES as u32);
    for i in 0..PAGES {
        fs = fs.file(&format!("f{i:02}"), &[(i as i32, 0, 1)]);
    }
    let slot = md5_slot(&vec![0; 8 * MIB]);
    let pages: Vec<_> = (0..PAGES).map(|_| (page.clone(), slot)).collect();
    let buf = archive_v2(&pages, &stored(&fs.finish()));
    let limits = Limits {
        max_page_len: 8 * MIB,
        ..Limits::default()
    };

    let archive = open_with(buf, limits).unwrap();
    let before = live();
    for (_, idx) in archive.walk() {
        check!(archive.read(idx).unwrap() == [0]);
    }
    let retained = (live() - before).max(0) as usize;
    check!(
        retained <= CEILING,
        "the cache retains {retained} bytes from a {}-byte page set",
        PAGES * page.len()
    );
}

#[test]
fn a_read_that_fails_reserves_no_more_than_its_pages_hold() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, i32::MAX)]).finish();
    let archive = open(digits_v2(&fsindex)).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    let (got, held) = peak(|| archive.read(idx));
    check!(let Err(Error::BlockOutOfPage { .. } | Error::FileTooLarge { .. }) = got);
    check!(
        held <= MIB,
        "a failing read of a 10-byte page held {held} bytes"
    );
}

/// Signature units each preceded by a head whose page tables fit, so validating each reads all of them.
///
/// The `0xFF` lead-in makes every size table sum past the file, so no candidate validates.
fn signature_field(len: usize) -> Vec<u8> {
    const UNIT: usize = 9 + 7;
    let mut buf = vec![0xFF; 32];
    while buf.len() + UNIT <= len {
        let pages = (buf.len() / 20) as u32;
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&pages.to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(cfs0002::SIGNATURE);
    }
    buf
}

/// The fastest of three opens of `buf`, which fails since no candidate validates.
fn time_open(buf: &[u8]) -> Duration {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            check!(let Err(Error::Trailer { .. }) = open(buf.to_vec()));
            started.elapsed()
        })
        .min()
        .unwrap()
}

#[test]
fn the_backward_scan_stays_linear_over_signature_bytes() {
    let small = time_open(&signature_field(128 << 10));
    let large = time_open(&signature_field(512 << 10));
    let ratio = large.as_secs_f64() / small.as_secs_f64();
    check!(
        ratio < 8.0,
        "4x the input took {ratio:.1}x the time ({small:?} -> {large:?})"
    );
}

/// Upstream's empty file is one zero-size block on page -1; any other negative field is refused.
#[test]
fn a_zero_size_block_is_skipped_whatever_its_page_and_offset() {
    let fsindex = Fsindex::new(1)
        .file("f", &[(i32::MIN, i32::MIN, 0), (0, 2, 3), (-7, -7, 0)])
        .finish();
    let archive = open(digits_v2(&fsindex)).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    assert!(let Kind::File(blocks) = &archive.node(idx).kind);
    check!(blocks.len() == 1);
    check!(archive.read(idx).unwrap() == b"234");
}

/// A block at the very end of a page, and one past it by a byte, at the largest offsets the format can hold.
#[test]
fn a_block_ending_exactly_at_its_page_reads_and_one_byte_more_does_not() {
    let fsindex = Fsindex::new(3)
        .file("end", &[(0, 9, 1)])
        .file("past", &[(0, 9, 2)])
        .file("far", &[(0, i32::MAX, i32::MAX)])
        .finish();
    let archive = open(digits_v2(&fsindex)).unwrap();
    let files: BTreeMap<String, _> = archive.walk().collect();
    check!(archive.read(files["end"]).unwrap() == b"9");
    check!(let Err(Error::BlockOutOfPage { page: 0, page_len: 10, .. }) = archive.read(files["past"]));
    check!(let Err(Error::BlockOutOfPage { .. } | Error::FileTooLarge { .. }) = archive.read(files["far"]));
}

/// Upstream dedups identical pages, so one page under every block of a file is a valid archive.
#[test]
fn a_page_under_every_block_of_a_file_reads_it_that_many_times() {
    const BLOCKS: usize = 100_000;
    let fsindex = Fsindex::new(1)
        .file("f", &vec![(0, 0, 10); BLOCKS])
        .finish();
    let archive = open(digits_v2(&fsindex)).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    let started = Instant::now();
    let data = archive.read(idx).unwrap();
    check!(data.len() == BLOCKS * 10);
    check!(data.chunks(10).all(|c| c == b"0123456789"));
    check!(
        started.elapsed() < TIME_BOUND,
        "{BLOCKS} blocks took {:?}",
        started.elapsed()
    );
}
