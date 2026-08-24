//! Shared helpers for reading `corpus.toml` and locating fetched samples.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Overrides where samples live; the corpus tool reads the same variable.
pub const DIR_ENV: &str = "COOKFS_CORPUS_DIR";

#[derive(Debug)]
pub struct Sample {
    pub name: String,
    pub sha256: String,
    pub size: u64,
    pub format: String,
    pub container: String,
}

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate manifest lives two levels under the workspace root")
        .to_path_buf()
}

pub fn samples_dir() -> PathBuf {
    env::var(DIR_ENV).map_or_else(|_| workspace_root().join("samples"), PathBuf::from)
}

pub fn manifest() -> Vec<Sample> {
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
