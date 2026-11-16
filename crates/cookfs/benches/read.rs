#![allow(
    clippy::unwrap_used,
    reason = "a bench that cannot read its input has nothing to measure"
)]

//! Opening archives and extracting every file, timed with allocations counted.
//!
//! The fixtures are small archives upstream wrote, one per codec and format,
//! so they measure per-blob overhead. The corpus samples are real installers,
//! where decoding dominates; they are skipped unless `tempo corpus -- pull`
//! has fetched them. Each iteration opens a fresh archive, so every page is
//! decoded cold, as a one-shot extraction would.

use std::path::{Path, PathBuf};

use cookfs::{Archive, OpenOptions};
use divan::{AllocProfiler, Bencher};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

/// One fixture per codec and format, plus the ones shaped to stress the index or page count.
const FIXTURES: &[&str] = &[
    "v2-none-md5",
    "v2-zlib-md5",
    "v2-bz2-md5",
    "v2-lzma-md5",
    "v3-none",
    "v3-zlib",
    "v3-bz2",
    "v3-lzma",
    "v3-zstd",
    "v3-brotli",
    "v3-many",
    "v3-tiny-pages",
];

/// Real installers small enough to sample repeatedly, `CFS0003` first.
const SAMPLES: &[&str] = &[
    "cookit-installer.x86_64-w64-mingw32.exe",
    "alfresco-community-deployment-4.2.f-win.exe",
    "idafree70_linux.run",
    "bitnami-resourcespace-6.0-0-module-windows-installer.exe",
];

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> Vec<u8> {
    let path = crate_dir()
        .join("tests/fixtures")
        .join(format!("{name}.cfs"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn sample(name: &str) -> Option<Vec<u8>> {
    let dir = std::env::var_os("COOKFS_CORPUS_DIR")
        .map_or_else(|| crate_dir().join("../../samples"), PathBuf::from);
    std::fs::read(dir.join(name)).ok()
}

/// Opens `buf` and reads every file in data order, returning the bytes read.
fn extract(buf: Vec<u8>) -> u64 {
    let archive = Archive::open(buf, &OpenOptions::default()).unwrap();
    archive
        .page_order()
        .into_iter()
        .map(|(_, id)| archive.read(id).unwrap().len() as u64)
        .sum()
}

/// As [`extract`], with files split across threads by page so each page is decoded by one thread.
fn extract_parallel(buf: Vec<u8>) -> u64 {
    let archive = Archive::open(buf, &OpenOptions::default()).unwrap();
    let files = archive.page_order();
    let workers = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    let per = files.len().div_ceil(workers).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = files
            .chunks(per)
            .map(|chunk| {
                let archive = &archive;
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|&(_, id)| archive.read(id).unwrap().len() as u64)
                        .sum::<u64>()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    })
}

#[divan::bench(args = FIXTURES)]
fn open(bencher: Bencher<'_, '_>, name: &str) {
    let buf = fixture(name);
    bencher
        .with_inputs(|| buf.clone())
        .bench_values(|buf| Archive::open(buf, &OpenOptions::default()).unwrap());
}

#[divan::bench(args = FIXTURES)]
fn extract_fixture(bencher: Bencher<'_, '_>, name: &str) {
    let buf = fixture(name);
    bencher.with_inputs(|| buf.clone()).bench_values(extract);
}

#[divan::bench(args = SAMPLES, sample_count = 10, sample_size = 1)]
fn extract_sample(bencher: Bencher<'_, '_>, name: &str) {
    let Some(buf) = sample(name) else {
        eprintln!("skipping {name}: not fetched; run `tempo corpus -- pull`");
        return;
    };
    bencher.with_inputs(|| buf.clone()).bench_values(extract);
}

#[divan::bench(args = SAMPLES, sample_count = 10, sample_size = 1)]
fn extract_sample_parallel(bencher: Bencher<'_, '_>, name: &str) {
    let Some(buf) = sample(name) else {
        eprintln!("skipping {name}: not fetched; run `tempo corpus -- pull`");
        return;
    };
    bencher
        .with_inputs(|| buf.clone())
        .bench_values(extract_parallel);
}
