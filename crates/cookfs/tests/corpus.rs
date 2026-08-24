//! Resolves and validates the sample corpus.
//!
//! An absent corpus skips and passes; a corpus that is present but broken fails loudly. The two
//! must never collapse into each other, or a run that checked nothing reports green.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use assert2::check;

/// Names the manifest CI syncs into a temp dir; unset locally, where `samples/` is used instead.
const MANIFEST_ENV: &str = "COOKFS_CORPUS_MANIFEST";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate manifest lives two levels under the workspace root")
        .to_path_buf()
}

/// `None` when no corpus is configured at all. A configured-but-missing manifest is a broken
/// setup, not an absent corpus, so it panics rather than degrading to a skip.
fn manifest_path() -> Option<PathBuf> {
    if let Ok(raw) = env::var(MANIFEST_ENV) {
        let path = PathBuf::from(&raw);
        assert!(
            path.is_file(),
            "{MANIFEST_ENV} is set to {raw}, which names no file"
        );
        return Some(path);
    }
    let local = workspace_root().join("samples").join("manifest.toml");
    local.is_file().then_some(local)
}

/// Fixture paths, relative to the manifest's own directory.
fn fixtures(manifest: &Path) -> Vec<PathBuf> {
    let text = fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest.display()));
    let table: toml::Table = text
        .parse()
        .unwrap_or_else(|e| panic!("{} is not valid TOML: {e}", manifest.display()));

    let entries = table
        .get("fixture")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{} declares no [[fixture]] entries", manifest.display()));

    entries
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("a [[fixture]] in {} has no `path`", manifest.display()));
            PathBuf::from(path)
        })
        .collect()
}

/// Digests are verified once when the corpus is fetched, so this only proves every listed
/// fixture materialized; rehashing multi-gigabyte samples per run would not be worth it.
#[test]
fn every_listed_fixture_resolves() {
    let Some(manifest) = manifest_path() else {
        eprintln!("skipping: no corpus (set {MANIFEST_ENV}, or populate samples/manifest.toml)");
        return;
    };
    let root = manifest
        .parent()
        .expect("a manifest file path has a parent directory");

    let fixtures = fixtures(&manifest);
    assert!(
        !fixtures.is_empty(),
        "{} lists zero fixtures",
        manifest.display()
    );

    for relative in fixtures {
        let path = root.join(&relative);
        let metadata = fs::metadata(&path).unwrap_or_else(|e| {
            panic!(
                "{} lists {}, which does not resolve: {e}",
                manifest.display(),
                relative.display()
            )
        });
        check!(metadata.len() > 0, "{} is empty", relative.display());
    }
}
