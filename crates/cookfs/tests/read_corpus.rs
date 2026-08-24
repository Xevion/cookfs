//! Opens every CFS0002 and CFS0003 sample in the corpus and walks its
//! directory tree.
//!
//! Samples whose `container` is `zip` hold their cookfs payload inside a zip
//! entry (macOS `.app` bundles), which this crate does not unpack; only
//! `container = "raw"` samples can be opened directly by path.

mod common;

use std::fs::{self, File};
use std::path::Path;

use assert2::check;
use common::{Sample, manifest, samples_dir};
use cookfs::{Archive, ArchiveVersion};

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

/// Samples in the corpus with a given format, restricted to `raw` containers.
fn raw_samples(format: &str) -> Vec<Sample> {
    manifest()
        .into_iter()
        .filter(|s| s.format == format && s.container == "raw")
        .collect()
}

fn opens_and_walks(format: &str) {
    let dir = samples_dir();
    if !dir.is_dir() {
        eprintln!(
            "skipping: no corpus at {} (run `tempo corpus -- pull`)",
            dir.display()
        );
        return;
    }

    let samples = raw_samples(format);
    assert!(
        !samples.is_empty(),
        "no raw {format} samples in corpus.toml"
    );

    for sample in samples {
        let file = open_sample(&dir, &sample);
        let archive =
            Archive::open(file).unwrap_or_else(|e| panic!("cannot open {}: {e}", sample.name));

        let entries = archive.walk();
        check!(!entries.is_empty(), "{} has an empty tree", sample.name);
    }
}

fn largest_file_reads_its_full_size(format: &str) {
    let dir = samples_dir();
    if !dir.is_dir() {
        eprintln!(
            "skipping: no corpus at {} (run `tempo corpus -- pull`)",
            dir.display()
        );
        return;
    }

    for sample in raw_samples(format) {
        let file = open_sample(&dir, &sample);
        let archive =
            Archive::open(file).unwrap_or_else(|e| panic!("cannot open {}: {e}", sample.name));

        let largest = archive
            .walk()
            .into_iter()
            .map(|(path, idx)| (archive.node(idx).size(), path, idx))
            .max_by_key(|(size, _, _)| *size);

        let Some((expected_size, path, idx)) = largest else {
            panic!("{} has no files at all", sample.name);
        };

        let bytes = archive
            .read(idx)
            .unwrap_or_else(|e| panic!("{}: cannot read {path}: {e}", sample.name));
        check!(
            bytes.len() as u64 == expected_size,
            "{}: {path} read {} bytes, node size says {expected_size}",
            sample.name,
            bytes.len()
        );
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
fn archive_version_matches_the_format_it_was_opened_from() {
    let dir = samples_dir();
    if !dir.is_dir() {
        eprintln!(
            "skipping: no corpus at {} (run `tempo corpus -- pull`)",
            dir.display()
        );
        return;
    }

    let cases = [
        ("CFS0002", ArchiveVersion::Cfs0002),
        ("CFS0003", ArchiveVersion::Cfs0003),
    ];
    for (format, expected) in cases {
        let Some(sample) = raw_samples(format).into_iter().next() else {
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
