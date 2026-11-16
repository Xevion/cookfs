//! Hostile inputs: every field at its boundaries, allocation bounds, and the cost of a scan.
//!
//! Archives here are assembled field by field, recording where each field lands,
//! so a sweep can set any one of them to a boundary value and check what the
//! reader does with it. A per-thread counting allocator measures what a call
//! holds, which is how "bounded allocation" is checked rather than assumed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use assert2::{assert, check};
use proptest::prelude::*;

use crate::codec::tests::{deflate, lzma_alone_stream, raw_lzma1_stream};
use crate::index::MAGIC;
use crate::index::tests::Fsindex;
use crate::parsers::{cfs0002, cfs0003};
use crate::{Archive, Error, Kind, Limits, OpenOptions};

/// Counts the bytes each thread holds, so a test can bound what one call allocates.
struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn track(delta: isize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + delta;
        live.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

// SAFETY: every method forwards to `System` with the caller's arguments and only adds bookkeeping.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            track(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            track(layout.size() as isize);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(ptr, layout) };
        track(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            track(new_size as isize - layout.size() as isize);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `f`, returning its result and the most bytes this thread held during it beyond what it held before.
fn peak<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let start = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(start));
    let out = f();
    let top = PEAK.with(Cell::get);
    (out, (top - start).max(0) as usize)
}

/// Bytes this thread holds right now.
fn live() -> isize {
    LIVE.with(Cell::get)
}

const MIB: usize = 1 << 20;

/// The text every compressed test page holds.
const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog, and the dog sleeps on";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    U8,
    Be32,
    Be64,
    Le32,
    Le64,
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    at: usize,
    width: Width,
}

impl Field {
    fn read(&self, buf: &[u8]) -> u64 {
        let b = &buf[self.at..];
        match self.width {
            Width::U8 => u64::from(b[0]),
            Width::Be32 => u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            Width::Le32 => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            Width::Be64 => u64::from_be_bytes(b[..8].try_into().unwrap()),
            Width::Le64 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        }
    }

    fn write(&self, buf: &mut [u8], value: u64) {
        let b = &mut buf[self.at..];
        match self.width {
            Width::U8 => b[0] = value as u8,
            Width::Be32 => b[..4].copy_from_slice(&(value as u32).to_be_bytes()),
            Width::Le32 => b[..4].copy_from_slice(&(value as u32).to_le_bytes()),
            Width::Be64 => b[..8].copy_from_slice(&value.to_be_bytes()),
            Width::Le64 => b[..8].copy_from_slice(&value.to_le_bytes()),
        }
    }

    /// The values worth trying here: the type's edges, its signed edges, and one either side of what it holds.
    fn boundaries(&self, buf: &[u8]) -> Vec<u64> {
        let orig = self.read(buf);
        let mut out = match self.width {
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
}

/// Bytes being assembled, with the place and width of every field written through [`Buf::put`].
#[derive(Default)]
struct Buf {
    bytes: Vec<u8>,
    fields: Vec<Field>,
}

impl Buf {
    fn put(&mut self, name: impl Into<String>, width: Width, value: u64) {
        self.fields.push(Field {
            name: name.into(),
            at: self.bytes.len(),
            width,
        });
        let field = self.fields.last().unwrap().clone();
        let len = match width {
            Width::U8 => 1,
            Width::Be32 | Width::Le32 => 4,
            Width::Be64 | Width::Le64 => 8,
        };
        self.bytes.resize(self.bytes.len() + len, 0);
        field.write(&mut self.bytes, value);
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn nest(&mut self, inner: Self) {
        let base = self.bytes.len();
        self.fields.extend(inner.fields.into_iter().map(|f| Field {
            at: f.at + base,
            ..f
        }));
        self.bytes.extend_from_slice(&inner.bytes);
    }
}

/// One fsindex entry for the annotated builder.
enum Entry {
    Dir(&'static str, Vec<Self>),
    File(&'static str, Vec<(i32, i32, i32)>),
}

fn entry(b: &mut Buf, e: &Entry) {
    let (name, count) = match e {
        Entry::Dir(name, _) => (*name, -1),
        Entry::File(name, blocks) => (*name, blocks.len() as i32),
    };
    b.put(format!("{name} name length"), Width::U8, name.len() as u64);
    b.raw(name.as_bytes());
    b.raw(&[0]);
    b.put(format!("{name} mtime"), Width::Be64, 1_700_000_000);
    b.put(
        format!("{name} block count"),
        Width::Be32,
        u64::from(count.cast_unsigned()),
    );
    match e {
        Entry::Dir(name, children) => {
            b.put(
                format!("{name} child count"),
                Width::Be32,
                children.len() as u64,
            );
            for child in children {
                entry(b, child);
            }
        }
        Entry::File(name, blocks) => {
            for (i, &(page, offset, size)) in blocks.iter().enumerate() {
                b.put(
                    format!("{name} block {i} page"),
                    Width::Be32,
                    u64::from(page.cast_unsigned()),
                );
                b.put(
                    format!("{name} block {i} offset"),
                    Width::Be32,
                    u64::from(offset.cast_unsigned()),
                );
                b.put(
                    format!("{name} block {i} size"),
                    Width::Be32,
                    u64::from(size.cast_unsigned()),
                );
            }
        }
    }
}

fn fsindex(root: &[Entry], metadata: &[&[u8]]) -> Buf {
    let mut b = Buf::default();
    b.raw(MAGIC);
    b.put("root child count", Width::Be32, root.len() as u64);
    for e in root {
        entry(&mut b, e);
    }
    b.put("metadata count", Width::Be32, metadata.len() as u64);
    for (i, record) in metadata.iter().enumerate() {
        b.put(
            format!("metadata {i} length"),
            Width::Be32,
            record.len() as u64,
        );
        b.raw(record);
    }
    b
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

/// An `.lzma`-alone page body with its 13-byte header split into fields.
fn lzma_alone_page(b: &mut Buf, page: usize) {
    let stream = lzma_alone_stream(TEXT);
    b.put(
        format!("page {page} lzma properties"),
        Width::U8,
        stream[0].into(),
    );
    b.put(
        format!("page {page} lzma dictionary"),
        Width::Le32,
        u32::from_le_bytes(stream[1..5].try_into().unwrap()).into(),
    );
    b.put(
        format!("page {page} lzma size"),
        Width::Le64,
        u64::from_le_bytes(stream[5..13].try_into().unwrap()),
    );
    b.raw(&stream[13..]);
}

/// A `CFS0002` archive over stored, zlib, `.lzma`-alone and (with the feature) bzip2 pages.
fn v2_base() -> Buf {
    let mut pages: Vec<(Buf, Option<u32>, &[u8])> = Vec::new();

    let mut p = Buf::default();
    p.put("page 0 codec", Width::U8, 0);
    p.raw(b"0123456789abcdef");
    pages.push((p, Some(16), b"0123456789abcdef"));

    let mut p = Buf::default();
    p.put("page 1 codec", Width::U8, 1);
    p.raw(&deflate(TEXT));
    pages.push((p, None, TEXT));

    let mut p = Buf::default();
    p.put("page 2 codec", Width::U8, 255);
    lzma_alone_page(&mut p, 2);
    pages.push((p, Some(TEXT.len() as u32), TEXT));

    #[cfg(feature = "codec-bzip2")]
    {
        let mut p = Buf::default();
        p.put("page 3 codec", Width::U8, 2);
        p.put("page 3 bzip2 size", Width::Be32, TEXT.len() as u64);
        p.raw(&crate::codec::tests::bzip2_stream(TEXT));
        pages.push((p, None, TEXT));
    }

    let text_pages: Vec<i32> = (1..pages.len() as i32).collect();
    let mut index = Buf::default();
    index.put("fsindex codec", Width::U8, 0);
    index.nest(fsindex(&tree(&text_pages), &[b"key\0value", b""]));

    let mut out = Buf::default();
    let lens: Vec<usize> = pages.iter().map(|(p, _, _)| p.bytes.len()).collect();
    let slots: Vec<(Option<u32>, &[u8])> = pages.iter().map(|&(_, d, text)| (d, text)).collect();
    for (p, _, _) in pages {
        out.nest(p);
    }
    for (i, &(declared, decoded)) in slots.iter().enumerate() {
        match declared {
            Some(len) => {
                out.raw(&[0; 8]);
                out.put(format!("page {i} slot size"), Width::Be32, len.into());
                out.raw(&crc32fast::hash(decoded).to_be_bytes());
            }
            None => out.raw(&cfs0002::tests::md5_slot(decoded)),
        }
    }
    for (i, len) in lens.iter().enumerate() {
        out.put(format!("page {i} stored length"), Width::Be32, *len as u64);
    }
    let index_len = index.bytes.len();
    out.nest(index);
    out.put("fsindex length", Width::Be32, index_len as u64);
    out.put("page count", Width::Be32, lens.len() as u64);
    out.put("default compression", Width::U8, 0);
    out.raw(cfs0002::SIGNATURE);
    out
}

/// One `CFS0003` page: its codec id, its body, and the length that body decodes to.
struct Page3 {
    codec: u8,
    body: Buf,
    plain: usize,
}

/// A `CFS0003` archive over stored, zlib, raw LZMA1 and (with the features) zstd and brotli pages.
fn v3_base() -> Buf {
    let mut pages = vec![Page3 {
        codec: 0,
        body: {
            let mut b = Buf::default();
            b.raw(b"0123456789abcdef");
            b
        },
        plain: 16,
    }];
    let mut b = Buf::default();
    b.raw(&deflate(TEXT));
    pages.push(Page3 {
        codec: 1,
        body: b,
        plain: TEXT.len(),
    });

    let stream = raw_lzma1_stream(TEXT);
    let mut b = Buf::default();
    b.put("page 2 lzma properties", Width::U8, stream[0].into());
    b.put(
        "page 2 lzma dictionary",
        Width::Le32,
        u32::from_le_bytes(stream[1..5].try_into().unwrap()).into(),
    );
    b.raw(&stream[5..]);
    pages.push(Page3 {
        codec: 3,
        body: b,
        plain: TEXT.len(),
    });

    #[cfg(feature = "codec-zstd")]
    {
        let mut b = Buf::default();
        b.raw(&crate::codec::tests::zstd_stream(TEXT));
        pages.push(Page3 {
            codec: 4,
            body: b,
            plain: TEXT.len(),
        });
    }
    #[cfg(feature = "codec-brotli")]
    {
        let mut b = Buf::default();
        b.raw(&crate::codec::tests::brotli_stream(TEXT));
        pages.push(Page3 {
            codec: 5,
            body: b,
            plain: TEXT.len(),
        });
    }

    let n = pages.len();
    let mut pgindex = Buf::default();
    pgindex.put("pgindex count", Width::Be32, n as u64);
    for (i, p) in pages.iter().enumerate() {
        pgindex.put(format!("page {i} codec"), Width::U8, p.codec.into());
    }
    pgindex.raw(&vec![0; 2 * n]);
    for (i, p) in pages.iter().enumerate() {
        pgindex.put(
            format!("page {i} stored length"),
            Width::Be32,
            p.body.bytes.len() as u64,
        );
    }
    for (i, p) in pages.iter().enumerate() {
        pgindex.put(
            format!("page {i} decoded length"),
            Width::Be32,
            p.plain as u64,
        );
    }
    pgindex.raw(&vec![0; 16 * n]);

    let text_pages: Vec<i32> = (1..n as i32).collect();
    let index = fsindex(&tree(&text_pages), &[b"key\0value", b""]);

    let mut out = Buf::default();
    for p in pages {
        out.nest(p.body);
    }
    let (pg_len, fs_len) = (pgindex.bytes.len() as u64, index.bytes.len() as u64);
    out.nest(pgindex);
    out.nest(index);
    out.put("base compression", Width::U8, 0);
    out.put("base level", Width::U8, 0);
    out.put("encryption", Width::U8, 0);
    for (blob, len) in [("pgindex", pg_len), ("fsindex", fs_len)] {
        out.put(format!("{blob} codec"), Width::U8, 0);
        out.put(format!("{blob} level"), Width::U8, 0);
        out.raw(&[0; 16]);
        out.put(format!("{blob} stored length"), Width::Be32, len);
        out.put(format!("{blob} decoded length"), Width::Be32, len);
    }
    out.raw(cfs0003::SIGNATURE);
    out
}

/// The limits a hostile input gets: small enough that a bound violation shows, large enough for every base page.
const TIGHT: Limits = Limits {
    max_fsindex_len: MIB,
    max_page_len: MIB,
    max_file_len: 16 * MIB as u64,
    max_depth: 32,
};

/// What one open and full read may hold: a few decoded pages, one output buffer, and decoder state.
const HELD_BOUND: usize = 32 * MIB;

const TIME_BOUND: Duration = Duration::from_secs(2);

/// Opens `buf` under tight limits and reads every file, returning what broke a bound.
fn bounded(buf: Vec<u8>) -> Result<(), String> {
    let opts = OpenOptions {
        limits: TIGHT,
        ..OpenOptions::default()
    };
    let started = Instant::now();
    let (outcome, held) = peak(move || {
        catch_unwind(AssertUnwindSafe(move || -> Result<(), String> {
            let Ok(archive) = Archive::open(buf, &opts) else {
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
        for value in field.boundaries(&base.bytes) {
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

fn read_all(buf: Vec<u8>, limits: Limits) -> Result<BTreeMap<String, Option<Vec<u8>>>, Error> {
    let archive = Archive::open(
        buf,
        &OpenOptions {
            limits,
            ..OpenOptions::default()
        },
    )?;
    archive
        .walk()
        .into_iter()
        .map(|(path, idx)| {
            let data = (!archive.node(idx).is_dir())
                .then(|| archive.read(idx))
                .transpose()?;
            Ok((path, data))
        })
        .collect()
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
                cfs0002::tests::md5_slot(page)
            } else {
                cfs0002::tests::crc_slot(page)
            };
            (blob, slot)
        })
        .collect();
    let mut index = vec![0u8];
    index.extend_from_slice(&fsindex_of(&root));
    cfs0002::tests::archive(&blobs, &index)
}

fn build_v3(files: &BTreeMap<Vec<String>, Vec<u8>>, page_len: usize) -> Vec<u8> {
    let (pages, root) = pack(files, page_len);
    cfs0003::tests::archive(&pages, &fsindex_of(&root), 0)
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
}

/// A chain of directories, each claiming as many children as the bytes after it could hold.
///
/// Every claim passes the remaining-bytes check on its own, but each directory
/// reserves for its claim, so the reservations add up across the chain.
fn inflated_chain(depth: usize, pad: usize) -> Vec<u8> {
    let claim = (pad / 14) as u32;
    let mut fs = Fsindex::new(1);
    for _ in 0..depth {
        fs = fs.dir("d", claim);
    }
    let mut blob = fs.finish();
    blob.truncate(blob.len() - 4); // no metadata: the parse fails before it
    blob.extend(std::iter::repeat_n(0u8, pad)); // zeros parse as empty-named files
    blob
}

/// The control for the chain below: as many entries, flat, held well within the bound.
#[test]
fn a_flat_tree_parses_within_a_small_multiple_of_its_size() {
    let pad = 256 << 10;
    let mut blob = Fsindex::new((pad / 14) as u32).finish();
    blob.truncate(blob.len() - 4);
    blob.extend(std::iter::repeat_n(0u8, pad / 14 * 14));
    blob.extend_from_slice(&0u32.to_be_bytes());
    let (parsed, held) = peak(|| crate::index::Index::parse(&blob, 512));
    assert!(parsed.is_ok());
    check!(
        held <= 16 * blob.len(),
        "held {held} for a {}-byte blob",
        blob.len()
    );
}

#[test]
fn inflated_child_counts_in_nested_directories_reserve_in_proportion_to_the_blob() {
    let blob = inflated_chain(500, 256 << 10);
    let (parsed, held) = peak(|| crate::index::Index::parse(&blob, 512));
    check!(parsed.is_err());
    check!(
        held <= 16 * blob.len(),
        "held {held} for a {}-byte blob",
        blob.len()
    );
}

/// A chain of long-named directories with many files at the bottom, stored uncompressed.
fn deep_wide(depth: usize, files: u32) -> Vec<u8> {
    let name = "n".repeat(255);
    let mut fs = Fsindex::new(1);
    for level in 0..depth {
        fs = fs.dir(&name, if level + 1 == depth { files } else { 1 });
    }
    for i in 0..files {
        fs = fs.file(&i.to_string(), &[]);
    }
    fs.finish()
}

#[test]
#[ignore = "BUG: walk materializes every full path, so its output grows as files x depth x name length"]
fn walk_output_stays_in_proportion_to_the_fsindex() {
    let blob = deep_wide(100, 1000);
    let index = crate::index::Index::parse(&blob, 512).unwrap();
    let total: usize = index.walk().iter().map(|(path, _)| path.len()).sum();
    check!(
        total <= 64 * blob.len(),
        "walk produced {total} path bytes from a {}-byte fsindex",
        blob.len()
    );
}

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
    let mut index = vec![0u8];
    index.extend_from_slice(&fs.finish());
    let slot = cfs0002::tests::md5_slot(&vec![0; 8 * MIB]);
    let pages: Vec<_> = (0..PAGES).map(|_| (page.clone(), slot)).collect();
    let buf = cfs0002::tests::archive(&pages, &index);
    let opts = OpenOptions {
        limits: Limits {
            max_page_len: 8 * MIB,
            ..Limits::default()
        },
        ..OpenOptions::default()
    };

    let archive = Archive::open(buf, &opts).unwrap();
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
    let page = (
        super::stored(b"0123456789"),
        cfs0002::tests::crc_slot(b"0123456789"),
    );
    let archive = super::open(cfs0002::tests::archive(&[page], &super::stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().into_iter().next().unwrap();
    let (got, held) = peak(|| archive.read(idx));
    check!(let Err(Error::BlockOutOfPage { .. } | Error::FileTooLarge { .. }) = got);
    check!(
        held <= MIB,
        "a failing read of a 10-byte page held {held} bytes"
    );
}

/// `max_depth` reads as the deepest directory nesting allowed, so that many nested directories should pass.
#[test]
fn max_depth_admits_exactly_that_many_nested_directories() {
    for depth in 1..=4 {
        let mut fs = Fsindex::new(1);
        for _ in 0..depth {
            fs = fs.dir("d", 1);
        }
        let blob = fs.file("f", &[]).finish();
        check!(
            crate::index::Index::parse(&blob, depth).is_ok(),
            "{depth} nested directories at max_depth {depth}"
        );
        check!(let Err(crate::IndexError::TooDeep { .. }) = crate::index::Index::parse(&blob, depth - 1));
    }
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
            check!(let Err(Error::Trailer { .. }) = super::open(buf.to_vec()));
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
    let page = (
        super::stored(b"0123456789"),
        cfs0002::tests::crc_slot(b"0123456789"),
    );
    let archive = super::open(cfs0002::tests::archive(&[page], &super::stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().into_iter().next().unwrap();
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
    let page = (
        super::stored(b"0123456789"),
        cfs0002::tests::crc_slot(b"0123456789"),
    );
    let archive = super::open(cfs0002::tests::archive(&[page], &super::stored(&fsindex))).unwrap();
    let files: BTreeMap<String, _> = archive.walk().into_iter().collect();
    check!(archive.read(files["end"]).unwrap() == b"9");
    check!(let Err(Error::BlockOutOfPage { .. }) = archive.read(files["past"]));
    check!(let Err(Error::BlockOutOfPage { .. } | Error::FileTooLarge { .. }) = archive.read(files["far"]));
}

/// Upstream dedups identical pages, so one page under every block of a file is a valid archive.
#[test]
fn a_page_under_every_block_of_a_file_reads_it_that_many_times() {
    const BLOCKS: usize = 100_000;
    let fsindex = Fsindex::new(1)
        .file("f", &vec![(0, 0, 10); BLOCKS])
        .finish();
    let page = (
        super::stored(b"0123456789"),
        cfs0002::tests::crc_slot(b"0123456789"),
    );
    let archive = super::open(cfs0002::tests::archive(&[page], &super::stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().into_iter().next().unwrap();
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

/// A million entries at the root, each the smallest an entry can be; sharing one empty name, the last stands.
#[test]
fn a_million_tiny_entries_open_and_walk_in_bounded_time() {
    const ENTRIES: u32 = 1_000_000;
    let mut blob = Fsindex::new(ENTRIES).finish();
    blob.truncate(blob.len() - 4);
    blob.extend(std::iter::repeat_n(0u8, ENTRIES as usize * 14));
    blob.extend_from_slice(&0u32.to_be_bytes());
    let started = Instant::now();
    let (index, held) = peak(|| crate::index::Index::parse(&blob, 512).unwrap());
    let walked = index.walk().len();
    check!(walked == 1);
    check!(
        held <= 16 * blob.len(),
        "held {held} for a {}-byte blob",
        blob.len()
    );
    check!(
        started.elapsed() < Duration::from_secs(10),
        "took {:?}",
        started.elapsed()
    );
}

/// Raw LZMA1 headers at every length short of whole, and property bytes past what LZMA allows.
#[test]
fn a_raw_lzma1_header_that_is_short_or_invalid_is_an_error() {
    use crate::codec::{Expect, decode};
    use crate::wire::Compression;
    let exact = |len| Expect {
        declared: Some(len),
        limit: MIB,
    };
    let stream = raw_lzma1_stream(TEXT);
    for len in 0..5 {
        check!(
            decode(Compression::LZMA, &stream[..len], exact(TEXT.len())).is_err(),
            "{len}-byte header"
        );
    }
    for props in [225u8, 0xFF] {
        let mut body = stream.clone();
        body[0] = props;
        check!(
            decode(Compression::LZMA, &body, exact(TEXT.len())).is_err(),
            "properties {props:#x}"
        );
    }
}

/// The legacy bzip2 size prefix is the only size an `md5`-mode page carries, so every edge of it is checked.
#[cfg(feature = "codec-bzip2")]
#[test]
fn a_legacy_bzip2_size_prefix_that_lies_is_an_error() {
    use crate::codec::{Expect, decode_prefixed};
    let stream = crate::codec::tests::bzip2_stream(TEXT);
    let blob = |size: u32| {
        let mut b = vec![2u8];
        b.extend_from_slice(&size.to_be_bytes());
        b.extend_from_slice(&stream);
        b
    };
    let free = Expect {
        declared: None,
        limit: MIB,
    };
    check!(decode_prefixed(&blob(TEXT.len() as u32), free).unwrap() == TEXT);
    for size in [0, 1, TEXT.len() as u32 - 1, TEXT.len() as u32 + 1, u32::MAX] {
        check!(decode_prefixed(&blob(size), free).is_err(), "prefix {size}");
    }
    for len in 0..5 {
        check!(
            decode_prefixed(&blob(TEXT.len() as u32)[..len], free).is_err(),
            "{len}-byte blob"
        );
    }
}

/// The process's peak virtual size, which moves for C allocations the counting allocator cannot see.
#[cfg(target_os = "linux")]
fn vm_peak() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmPeak:")).unwrap();
    let kib: usize = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    kib << 10
}

/// Found by the `codec_zstd` fuzz target: a 10-byte frame declaring a 128 MiB window and no content size.
#[cfg(all(target_os = "linux", feature = "codec-zstd"))]
#[test]
fn a_zstd_window_cannot_reserve_past_the_output_limit() {
    use crate::codec::{Expect, decode};
    use crate::wire::Compression;
    let frame = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x88, 0x09, 0x00, 0x00, b'A'];
    let expect = Expect {
        declared: None,
        limit: 64 << 10,
    };
    let before = vm_peak();
    // Upstream never writes a window past its content, so refusing the frame is as good as decoding it.
    let got = decode(Compression::ZSTD, &frame, expect);
    check!(got.as_deref().map_or(true, |out| out == b"A"));
    let grew = vm_peak().saturating_sub(before);
    check!(
        grew < 16 * MIB,
        "decoding one byte under a 64 KiB limit grew the process by {grew} bytes"
    );
}

/// Two brotli streams whose windows dwarf what they decode to.
///
/// The first has the largest standard window, its data split over two
/// metablocks so the decoder cannot size down. The second, found by the
/// `codec_brotli` fuzz target, opens with the large-window signature `0x11`.
#[cfg(feature = "codec-brotli")]
#[test]
fn a_brotli_window_stays_within_the_standard_maximum() {
    use std::io::Write;

    use crate::codec::{Expect, decode};
    use crate::wire::Compression;
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 1, 24);
    encoder.write_all(b"first metablock").unwrap();
    encoder.flush().unwrap();
    encoder.write_all(b", then a second").unwrap();
    let standard = encoder.into_inner();
    let large: Vec<u8> = std::iter::once(0x11)
        .chain(std::iter::repeat_n(0x1D, 122))
        .collect();
    let over: Vec<String> = [(standard, None), (large, Some(53_098))]
        .into_iter()
        .filter_map(|(stream, declared)| {
            let expect = Expect {
                declared,
                limit: 64 << 10,
            };
            let (_, held) = peak(|| decode(Compression::BROTLI, &stream, expect));
            // 16 MiB is the largest window standard brotli can name.
            (held > 17 * MIB).then(|| {
                format!(
                    "a {}-byte stream under a 64 KiB limit held {held} bytes",
                    stream.len()
                )
            })
        })
        .collect();
    check!(over.is_empty(), "{}", over.join("\n"));
}
