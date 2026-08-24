//! Checks `corpus.toml`, and the samples it names when they have been fetched.
//!
//! An absent corpus skips; one that is present but wrong fails. Collapsing those two would let a
//! run that checked nothing report green.

mod common;

use std::fs;

use assert2::check;
use common::{manifest, samples_dir};

#[test]
fn the_manifest_is_well_formed() {
    let samples = manifest();
    assert!(!samples.is_empty(), "corpus.toml lists zero samples");

    let mut names: Vec<&str> = samples.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    let unique = names.len();
    names.dedup();
    check!(names.len() == unique, "corpus.toml repeats a sample name");

    for sample in &samples {
        check!(sample.size > 0, "{} has size 0", sample.name);
        check!(
            sample.sha256.len() == 64 && sample.sha256.chars().all(|c| c.is_ascii_hexdigit()),
            "{} has a malformed sha256",
            sample.name
        );
        check!(
            matches!(sample.format.as_str(), "CFS0002" | "CFS0003" | "none"),
            "{} has an unknown format {:?}",
            sample.name,
            sample.format
        );
        check!(
            matches!(sample.container.as_str(), "raw" | "zip"),
            "{} has an unknown container {:?}",
            sample.name,
            sample.container
        );
    }
}

/// Sizes, not digests: the fetch hashes every byte on the way in.
#[test]
fn every_sample_resolves() {
    let dir = samples_dir();
    if !dir.is_dir() {
        eprintln!(
            "skipping: no corpus at {} (run `tempo corpus -- pull`)",
            dir.display()
        );
        return;
    }

    for sample in manifest() {
        let path = dir.join(&sample.name);
        let metadata = fs::metadata(&path).unwrap_or_else(|e| {
            panic!(
                "corpus.toml lists {}, which does not resolve: {e}",
                sample.name
            )
        });
        check!(
            metadata.len() == sample.size,
            "{} is {} bytes, manifest says {}",
            sample.name,
            metadata.len(),
            sample.size
        );
    }
}
