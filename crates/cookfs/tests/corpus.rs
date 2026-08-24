//! Checks `corpus.toml`, and the samples it names when they have been fetched.
//!
//! An absent corpus skips; one that is present but wrong fails. Collapsing those two would let a
//! run that checked nothing report green.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use assert2::check;

/// Overrides where samples live; the corpus tool reads the same variable.
const DIR_ENV: &str = "COOKFS_CORPUS_DIR";

#[derive(Debug)]
struct Sample {
    name: String,
    sha256: String,
    size: u64,
    format: String,
    container: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate manifest lives two levels under the workspace root")
        .to_path_buf()
}

fn samples_dir() -> PathBuf {
    env::var(DIR_ENV).map_or_else(|_| workspace_root().join("samples"), PathBuf::from)
}

fn manifest() -> Vec<Sample> {
    let path = workspace_root().join("corpus.toml");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let table: toml::Table = text
        .parse()
        .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}", path.display()));

    let entries = table
        .get("sample")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{} declares no [[sample]] entries", path.display()));

    let field = |entry: &toml::Value, key: &str| -> String {
        entry
            .get(key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("a [[sample]] in {} has no `{key}`", path.display()))
            .to_owned()
    };

    entries
        .iter()
        .map(|entry| Sample {
            name: field(entry, "name"),
            sha256: field(entry, "sha256"),
            format: field(entry, "format"),
            container: field(entry, "container"),
            size: entry
                .get("size")
                .and_then(toml::Value::as_integer)
                .and_then(|n| u64::try_from(n).ok())
                .unwrap_or_else(|| {
                    panic!("a [[sample]] in {} has no usable `size`", path.display())
                }),
        })
        .collect()
}

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
