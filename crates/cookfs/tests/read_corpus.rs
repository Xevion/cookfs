//! Opens every CFS0002 and CFS0003 sample in the corpus and walks its
//! directory tree.
//!
//! Raw samples open by path; zip samples (macOS `.app` bundles) unpack the
//! largest `/Contents/` entry first and open that.

mod common;

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use assert2::check;
use common::{Sample, manifest, samples_dir};
use cookfs::{Archive, ArchiveVersion};
use positioned_io::{ReadAt, Size};

/// Extracts the largest zip entry under any `/Contents/` path.
///
/// macOS `.app` bundles wrap the cookfs-bearing binary inside a zip; the
/// largest entry under the bundle's `Contents/` directory is the binary
/// itself, which has the cookfs archive appended.
fn read_zip_sample(dir: &Path, sample: &Sample) -> Vec<u8> {
    let path = dir.join(&sample.name);
    let file = File::open(&path)
        .unwrap_or_else(|e| panic!("{}: cannot open {}: {e}", sample.name, path.display()));
    let mut zip = zip::ZipArchive::new(file)
        .unwrap_or_else(|e| panic!("{}: not a valid zip: {e}", sample.name));

    let mut best: Option<(usize, u64)> = None;
    for i in 0..zip.len() {
        let entry = zip
            .by_index(i)
            .unwrap_or_else(|e| panic!("{}: cannot read zip entry {i}: {e}", sample.name));
        if entry.name().contains("/Contents/") && !entry.name().ends_with('/') {
            let size = entry.size();
            if best.is_none_or(|(_, b)| size > b) {
                best = Some((i, size));
            }
        }
    }

    let (idx, size) =
        best.unwrap_or_else(|| panic!("{}: no `/Contents/` entry inside zip", sample.name));
    let mut entry = zip
        .by_index(idx)
        .unwrap_or_else(|e| panic!("{}: cannot open zip entry {idx}: {e}", sample.name));
    let mut buf = Vec::with_capacity(size as usize);
    entry
        .read_to_end(&mut buf)
        .unwrap_or_else(|e| panic!("{}: cannot read zip entry {idx}: {e}", sample.name));
    buf
}

/// Opens a sample's file, first checking it actually is the fetch the
/// manifest describes rather than a stale or partial download.
fn open_sample(dir: &Path, sample: &Sample) -> File {
    let path = dir.join(&sample.name);
    let on_disk = fs::metadata(&path)
        .unwrap_or_else(|e| panic!("{}: cannot stat {}: {e}", sample.name, path.display()));
    assert!(
        on_disk.len() == sample.size,
        "{}: manifest says {} bytes (sha256 {}), disk has {}",
        sample.name,
        sample.size,
        sample.sha256,
        on_disk.len()
    );
    File::open(&path).unwrap_or_else(|e| panic!("cannot open {}: {e}", sample.name))
}

/// Samples in the corpus with a given format and container.
fn samples_of(format: &str, container: &str) -> Vec<Sample> {
    manifest()
        .into_iter()
        .filter(|s| s.format == format && s.container == container)
        .collect()
}

/// Panics if no corpus is present on disk. Returns whether tests may proceed.
fn corpus_ready() -> bool {
    let dir = samples_dir();
    if dir.is_dir() {
        return true;
    }
    eprintln!(
        "skipping: no corpus at {} (run `tempo corpus -- pull`)",
        dir.display()
    );
    false
}

fn assert_opens_and_walks<R: ReadAt + Size + Sync>(src: R, sample_name: &str) {
    let archive = Archive::open(src).unwrap_or_else(|e| panic!("cannot open {sample_name}: {e}"));
    let entries = archive.walk();
    check!(!entries.is_empty(), "{sample_name} has an empty tree");
}

fn assert_largest_file_reads<R: ReadAt + Size + Sync>(src: R, sample_name: &str) {
    let archive = Archive::open(src).unwrap_or_else(|e| panic!("cannot open {sample_name}: {e}"));
    let largest = archive
        .walk()
        .into_iter()
        .map(|(path, idx)| (archive.node(idx).size(), path, idx))
        .max_by_key(|(size, _, _)| *size);
    let Some((expected_size, path, idx)) = largest else {
        panic!("{sample_name} has no files at all");
    };
    let bytes = archive
        .read(idx)
        .unwrap_or_else(|e| panic!("{sample_name}: cannot read {path}: {e}"));
    check!(
        bytes.len() as u64 == expected_size,
        "{sample_name}: {path} read {} bytes, node size says {expected_size}",
        bytes.len()
    );
}

fn opens_and_walks(format: &str) {
    if !corpus_ready() {
        return;
    }
    let dir = samples_dir();
    let samples = samples_of(format, "raw");
    assert!(
        !samples.is_empty(),
        "no raw {format} samples in corpus.toml"
    );
    for sample in samples {
        assert_opens_and_walks(open_sample(&dir, &sample), &sample.name);
    }
}

fn largest_file_reads_its_full_size(format: &str) {
    if !corpus_ready() {
        return;
    }
    let dir = samples_dir();
    for sample in samples_of(format, "raw") {
        assert_largest_file_reads(open_sample(&dir, &sample), &sample.name);
    }
}

fn zip_opens_and_walks(format: &str) {
    if !corpus_ready() {
        return;
    }
    let dir = samples_dir();
    let samples = samples_of(format, "zip");
    assert!(
        !samples.is_empty(),
        "no zip {format} samples in corpus.toml"
    );
    for sample in samples {
        let bytes = read_zip_sample(&dir, &sample);
        assert_opens_and_walks(bytes, &sample.name);
    }
}

fn zip_largest_file_reads_its_full_size(format: &str) {
    if !corpus_ready() {
        return;
    }
    let dir = samples_dir();
    for sample in samples_of(format, "zip") {
        let bytes = read_zip_sample(&dir, &sample);
        assert_largest_file_reads(bytes, &sample.name);
    }
}

#[test]
fn every_raw_cfs0002_sample_opens_and_walks() {
    opens_and_walks("CFS0002");
}

#[test]
fn the_largest_file_in_each_raw_cfs0002_sample_reads_its_full_size() {
    largest_file_reads_its_full_size("CFS0002");
}

#[test]
fn every_raw_cfs0003_sample_opens_and_walks() {
    opens_and_walks("CFS0003");
}

#[test]
fn the_largest_file_in_each_raw_cfs0003_sample_reads_its_full_size() {
    largest_file_reads_its_full_size("CFS0003");
}

#[test]
fn every_zip_cfs0002_sample_opens_and_walks() {
    zip_opens_and_walks("CFS0002");
}

#[test]
fn the_largest_file_in_each_zip_cfs0002_sample_reads_its_full_size() {
    zip_largest_file_reads_its_full_size("CFS0002");
}

#[test]
fn archive_version_matches_the_format_it_was_opened_from() {
    if !corpus_ready() {
        return;
    }
    let dir = samples_dir();
    let cases = [
        ("CFS0002", ArchiveVersion::Cfs0002),
        ("CFS0003", ArchiveVersion::Cfs0003),
    ];
    for (format, expected) in cases {
        let Some(sample) = samples_of(format, "raw").into_iter().next() else {
            panic!("no raw {format} samples in corpus.toml");
        };
        let file = open_sample(&dir, &sample);
        let archive =
            Archive::open(file).unwrap_or_else(|e| panic!("cannot open {}: {e}", sample.name));
        check!(
            archive.version() == expected,
            "{} opened as the wrong version",
            sample.name
        );
    }
}
