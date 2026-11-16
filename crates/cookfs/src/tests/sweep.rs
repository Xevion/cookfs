//! Every field of an archive set to its boundary values: no panic, no allocation or time past a bound.
//!
//! The base archives here are assembled field by field, recording where each
//! field lands, so a sweep can set any one of them to a boundary value and
//! check what the reader does with it.

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use assert2::check;
use proptest::prelude::*;

use super::alloc::peak;
use super::kit::{
    Buf, Entry, Field, Fsindex, MIB, Page3, TIME_BOUND, Width, assemble_v2, assemble_v3, crc_slot,
    md5_slot, one_file_v2, one_file_v3, open_with, read_all,
};
use crate::Limits;
use crate::codec::testing::{TEXT, deflate, lzma_alone_stream, raw_lzma1_stream};

/// The limits a hostile input gets: small enough that a bound violation shows, large enough for every base page.
const TIGHT: Limits = Limits {
    max_fsindex_len: MIB,
    max_page_len: MIB,
    max_file_len: 16 * MIB as u64,
    max_depth: 32,
};

/// What one open and full read may hold: a few decoded pages, one output buffer, and decoder state.
const HELD_BOUND: usize = 32 * MIB;

/// The values worth trying in `field`: the type's edges, its signed edges, and one either side of what it holds.
fn boundaries(field: &Field, buf: &[u8]) -> Vec<u64> {
    let orig = field.read(buf);
    let mut out = match field.width {
        Width::U8 => vec![0, 1, 2, 3, 4, 5, 0x7F, 0x80, 0xFE, 0xFF],
        Width::Be32 | Width::Le32 => vec![
            0,
            1,
            2,
            0x7FFF_FFFE,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFE,
            0xFFFF_FFFF,
            buf.len() as u64,
        ],
        Width::Be64 | Width::Le64 => vec![
            0,
            1,
            i64::MAX as u64,
            i64::MIN as u64,
            u64::MAX,
            u64::MAX - 1,
        ],
    };
    out.extend([orig.wrapping_sub(1), orig.wrapping_add(1)]);
    out.retain(|&v| v != orig);
    out.sort_unstable();
    out.dedup();
    out
}

/// The tree both base archives carry: blocks across every page, nesting, an empty file and an empty directory.
fn tree(text_pages: &[i32]) -> Vec<Entry> {
    let text = TEXT.len() as i32;
    let mut root = vec![
        Entry::Dir(
            "d",
            vec![
                Entry::File("a", vec![(0, 0, 5), (text_pages[0], 2, 10)]),
                Entry::Dir("e", vec![Entry::File("b", vec![(text_pages[1], 0, text)])]),
            ],
        ),
        Entry::File("empty", vec![(-1, 0, 0)]),
        Entry::Dir("z", vec![]),
    ];
    for (i, &page) in text_pages.iter().enumerate().skip(2) {
        let name = ["c2", "c3", "c4", "c5"][i - 2];
        root.push(Entry::File(name, vec![(page, 4, text - 4)]));
    }
    root
}

/// The recorded fsindex both base archives carry, over text on every page after the first.
fn base_fsindex(pages: usize) -> Buf {
    let text_pages: Vec<i32> = (1..pages as i32).collect();
    let root = tree(&text_pages);
    Fsindex::recording(root.len() as u32)
        .tree(&root)
        .finish_buf(&[b"key\0value", b""])
}

/// An `.lzma`-alone page body with its 13-byte header split into fields.
fn lzma_alone_page(b: &mut Buf, page: usize) {
    let stream = lzma_alone_stream(TEXT);
    b.put(
        format_args!("page {page} lzma properties"),
        Width::U8,
        stream[0].into(),
    );
    b.put(
        format_args!("page {page} lzma dictionary"),
        Width::Le32,
        u32::from_le_bytes(stream[1..5].try_into().unwrap()).into(),
    );
    b.put(
        format_args!("page {page} lzma size"),
        Width::Le64,
        u64::from_le_bytes(stream[5..13].try_into().unwrap()),
    );
    b.raw(&stream[13..]);
}

/// A `CFS0002` archive over stored, zlib, `.lzma`-alone and (with the feature) bzip2 pages.
fn v2_base() -> Buf {
    let page = |i: usize, codec: u8| {
        let mut p = Buf::new(true);
        p.put(format_args!("page {i} codec"), Width::U8, codec.into());
        p
    };
    let mut pages = Vec::new();

    let mut p = page(0, 0);
    p.raw(b"0123456789abcdef");
    pages.push((p, crc_slot(b"0123456789abcdef")));

    let mut p = page(1, 1);
    p.raw(&deflate(TEXT));
    pages.push((p, md5_slot(TEXT)));

    let mut p = page(2, 255);
    lzma_alone_page(&mut p, 2);
    pages.push((p, crc_slot(TEXT)));

    #[cfg(feature = "codec-bzip2")]
    {
        let mut p = page(3, 2);
        p.put(
            format_args!("page 3 bzip2 size"),
            Width::Be32,
            TEXT.len() as u64,
        );
        p.raw(&crate::codec::testing::bzip2_stream(TEXT));
        pages.push((p, md5_slot(TEXT)));
    }

    let mut index = Buf::new(true);
    index.put(format_args!("fsindex codec"), Width::U8, 0);
    index.nest(base_fsindex(pages.len()));
    assemble_v2(pages, index)
}

/// A `CFS0003` archive over stored, zlib, raw LZMA1 and (with the features) zstd and brotli pages.
fn v3_base() -> Buf {
    let page = |codec: u8, body: Buf, plain: usize| Page3 { codec, body, plain };
    let mut pages = vec![page(0, Buf::of(b"0123456789abcdef"), 16)];
    pages.push(page(1, Buf::of(&deflate(TEXT)), TEXT.len()));

    let stream = raw_lzma1_stream(TEXT);
    let mut b = Buf::new(true);
    b.put(
        format_args!("page 2 lzma properties"),
        Width::U8,
        stream[0].into(),
    );
    b.put(
        format_args!("page 2 lzma dictionary"),
        Width::Le32,
        u32::from_le_bytes(stream[1..5].try_into().unwrap()).into(),
    );
    b.raw(&stream[5..]);
    pages.push(page(3, b, TEXT.len()));

    #[cfg(feature = "codec-zstd")]
    pages.push(page(
        4,
        Buf::of(&crate::codec::testing::zstd_stream(TEXT)),
        TEXT.len(),
    ));
    #[cfg(feature = "codec-brotli")]
    pages.push(page(
        5,
        Buf::of(&crate::codec::testing::brotli_stream(TEXT)),
        TEXT.len(),
    ));

    let index = base_fsindex(pages.len());
    assemble_v3(pages, index, 0)
}

/// Opens `buf` under tight limits and reads every file, returning what broke a bound.
fn bounded(buf: Vec<u8>) -> Result<(), String> {
    let started = Instant::now();
    let (outcome, held) = peak(move || {
        catch_unwind(AssertUnwindSafe(move || -> Result<(), String> {
            let Ok(archive) = open_with(buf, TIGHT) else {
                return Ok(());
            };
            for (path, idx) in archive.walk() {
                if let Ok(data) = archive.read(idx) {
                    let size = archive.node(idx).size();
                    if data.len() as u64 != size {
                        return Err(format!(
                            "{path} read {} bytes, its blocks sum to {size}",
                            data.len()
                        ));
                    }
                }
            }
            Ok(())
        }))
    });
    let elapsed = started.elapsed();
    match outcome {
        Err(_) => return Err("panicked".into()),
        Ok(Err(why)) => return Err(why),
        Ok(Ok(())) => {}
    }
    if held > HELD_BOUND {
        return Err(format!("held {held} bytes"));
    }
    if elapsed > TIME_BOUND {
        return Err(format!("took {elapsed:?}"));
    }
    Ok(())
}

/// Every field set to every one of its boundary values, one at a time: how many cases ran, and which broke a bound.
fn sweep(base: &Buf) -> (usize, Vec<String>) {
    let mut cases = 0;
    let mut failures = Vec::new();
    for field in &base.fields {
        for value in boundaries(field, &base.bytes) {
            let mut buf = base.bytes.clone();
            field.write(&mut buf, value);
            cases += 1;
            if let Err(why) = bounded(buf) {
                failures.push(format!("{} = {value:#x}: {why}", field.name));
            }
        }
    }
    (cases, failures)
}

/// What both base archives hold, page-for-page.
fn base_contents(pages_after_stored: usize) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = BTreeMap::new();
    let mut a = b"01234".to_vec();
    a.extend_from_slice(&TEXT[2..12]);
    want.insert("d".to_owned(), None);
    want.insert("d/a".to_owned(), Some(a));
    want.insert("d/e".to_owned(), None);
    want.insert("d/e/b".to_owned(), Some(TEXT.to_vec()));
    want.insert("empty".to_owned(), Some(Vec::new()));
    want.insert("z".to_owned(), None);
    for name in ["c2", "c3", "c4", "c5"]
        .iter()
        .take(pages_after_stored.saturating_sub(2))
    {
        want.insert((*name).to_owned(), Some(TEXT[4..].to_vec()));
    }
    want
}

#[test]
fn the_base_archives_read_back_what_they_were_built_from() {
    let v2 = v2_base();
    let pages = v2
        .fields
        .iter()
        .filter(|f| f.name.ends_with("stored length"))
        .count();
    check!(read_all(v2.bytes, TIGHT).unwrap() == base_contents(pages - 1));

    let v3 = v3_base();
    let pages = v3
        .fields
        .iter()
        .filter(|f| f.name.starts_with("page") && f.name.ends_with("stored length"))
        .count();
    check!(read_all(v3.bytes, TIGHT).unwrap() == base_contents(pages - 1));
}

#[test]
fn every_cfs0002_field_at_every_boundary_stays_bounded() {
    let (cases, failures) = sweep(&v2_base());
    check!(cases > 400);
    check!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_cfs0003_field_at_every_boundary_stays_bounded() {
    let (cases, failures) = sweep(&v3_base());
    check!(cases > 400);
    check!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `base` with a few of its bytes replaced, wherever they fall: names, hashes and contents as well as fields.
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
    /// Any few fields of a base archive set to any values at once: no panic, no allocation past the bound.
    #[test]
    fn several_fields_set_at_once_stay_bounded(
        v3 in any::<bool>(),
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u64>()), 1..5),
    ) {
        let base = if v3 { v3_base() } else { v2_base() };
        let mut buf = base.bytes.clone();
        for (field, value) in &edits {
            base.fields[field.index(base.fields.len())].write(&mut buf, *value);
        }
        prop_assert_eq!(bounded(buf), Ok(()));
    }

    #[test]
    fn a_corrupted_one_file_archive_stays_bounded(
        buf in any::<bool>().prop_flat_map(|v3| {
            mutated(if v3 { one_file_v3(b"hello v3!") } else { one_file_v2(b"hello world!") })
        }),
    ) {
        prop_assert_eq!(bounded(buf), Ok(()));
    }
}
