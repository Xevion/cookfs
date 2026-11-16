//! One case per corpus sample and per fixture: open it, read every file, and diff against upstream.
//!
//! Upstream's listing comes from `tempo oracle -- dump`, which reads each sample
//! through the real Tcl cookfs. Without a listing a case still checks that every
//! file reads. A missing sample or listing makes the case
//! ignored, never passed. `COOKFS_REQUIRE_CORPUS` and `COOKFS_REQUIRE_ORACLE`
//! turn those into failures, so CI cannot go green having checked nothing.

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use common::{Sample, manifest, samples_dir, workspace_root};
use cookfs::{Archive, Kind, OpenOptions};
use libtest_mimic::{Arguments, Failed, Trial};
use positioned_io::{ReadAt, Size};

/// Divergences printed per sample; the count covers the rest.
const SHOWN: usize = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir {
        mtime: i64,
    },
    File {
        size: u64,
        mtime: i64,
        crc: u32,
    },
    /// A name holding a slash, which upstream lists but cannot open.
    Unaddressable,
}

fn oracle_dir() -> PathBuf {
    std::env::var_os("COOKFS_ORACLE_DIR").map_or_else(
        || workspace_root().join("target").join("oracle"),
        PathBuf::from,
    )
}

fn required(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty() && v != "0")
}

fn parse_listing(text: &str) -> Result<BTreeMap<String, Entry>, String> {
    text.lines()
        .map(|line| {
            let fields: Vec<&str> = line.splitn(5, '\t').collect();
            let [kind, size, mtime, crc, path] = fields[..] else {
                return Err(format!("malformed listing line {line:?}"));
            };
            let num = |s: &str| s.parse::<i64>().map_err(|e| format!("{line:?}: {e}"));
            let entry = match kind {
                "dir" => Entry::Dir { mtime: num(mtime)? },
                "file" => Entry::File {
                    size: num(size)?.unsigned_abs(),
                    mtime: num(mtime)?,
                    crc: u32::from_str_radix(crc, 16).map_err(|e| format!("{line:?}: {e}"))?,
                },
                "unaddressable" => Entry::Unaddressable,
                other => return Err(format!("unknown kind {other:?}")),
            };
            Ok((path.to_owned(), entry))
        })
        .collect()
}

/// Every entry as this crate reads it, failing on the first unreadable file or repeated path.
///
/// Files are read in the order their data sits in the archive, since path order
/// revisits pages far more often than a bounded cache holds them.
fn read_all<R: ReadAt + Size>(archive: &Archive<R>) -> Result<BTreeMap<String, Entry>, String> {
    let mut nodes = archive.walk();
    nodes.sort_by_key(|&(_, idx)| match &archive.node(idx).kind {
        Kind::File(blocks) => blocks.first().map(|b| (b.page, b.offset)),
        _ => None,
    });

    let mut out = BTreeMap::new();
    for (path, idx) in nodes {
        let node = archive.node(idx);
        let entry = if node.name.contains('/') {
            Entry::Unaddressable
        } else if node.is_dir() {
            Entry::Dir { mtime: node.mtime }
        } else {
            let data = archive.read(idx).map_err(|e| format!("{path}: {e}"))?;
            Entry::File {
                size: data.len() as u64,
                mtime: node.mtime,
                crc: crc32fast::hash(&data),
            }
        };
        if out.insert(path.clone(), entry).is_some() {
            return Err(format!("{path} is listed twice"));
        }
    }
    Ok(out)
}

fn diff(ours: &BTreeMap<String, Entry>, upstream: &BTreeMap<String, Entry>) -> Vec<String> {
    let mut out = Vec::new();
    for (path, want) in upstream {
        match ours.get(path) {
            None => out.push(format!("missing: {path}")),
            Some(got) if got != want => {
                out.push(format!("{path}: upstream {want:?}, ours {got:?}"));
            }
            Some(_) => {}
        }
    }
    out.extend(
        ours.keys()
            .filter(|path| !upstream.contains_key(*path))
            .map(|path| format!("extra: {path}")),
    );
    out
}

/// The largest entry under a `.app` bundle's `Contents/`, which is the binary the archive rides on.
fn unzip(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut best: Option<(usize, u64)> = None;
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(|e| e.to_string())?;
        if entry.name().contains("/Contents/")
            && !entry.is_dir()
            && best.is_none_or(|(_, size)| entry.size() > size)
        {
            best = Some((i, entry.size()));
        }
    }
    let (idx, _) = best.ok_or("no entry under /Contents/")?;
    let mut buf = Vec::new();
    zip.by_index(idx)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

fn check<R: ReadAt + Size>(src: R, listing: Option<&Path>) -> Result<(), Failed> {
    let archive = Archive::open(src, &OpenOptions::default()).map_err(|e| format!("open: {e}"))?;
    let ours = read_all(&archive)?;
    if ours.is_empty() && listing.is_none() {
        return Err("the tree is empty and there is no listing to say it should be".into());
    }
    let Some(listing) = listing else {
        return Ok(());
    };

    let text = fs::read_to_string(listing).map_err(|e| format!("{}: {e}", listing.display()))?;
    let problems = diff(&ours, &parse_listing(&text)?);
    if problems.is_empty() {
        return Ok(());
    }
    let mut report = format!("{} divergences from upstream:\n", problems.len());
    for line in problems.iter().take(SHOWN) {
        let _ = writeln!(report, "  {line}");
    }
    Err(report.into())
}

fn trial(sample: Sample, dir: &Path, listings: &Path) -> Trial {
    let path = dir.join(&sample.name);
    let listing = listings.join(format!("{}.tsv", sample.name));
    let ignored = !path.is_file() && !required("COOKFS_REQUIRE_CORPUS");

    Trial::test(sample.name.clone(), move || {
        let on_disk =
            fs::metadata(&path).map_err(|e| format!("{} is not fetched: {e}", sample.name))?;
        if on_disk.len() != sample.size {
            return Err(format!(
                "{} bytes on disk, corpus.toml says {} (sha256 {})",
                on_disk.len(),
                sample.size,
                sample.sha256
            )
            .into());
        }
        let listing = if listing.is_file() {
            Some(listing.as_path())
        } else if required("COOKFS_REQUIRE_ORACLE") {
            return Err(format!(
                "no upstream listing at {}; run `tempo oracle -- dump`",
                listing.display()
            )
            .into());
        } else {
            None
        };

        if sample.container == "zip" {
            check(unzip(&path)?, listing)
        } else {
            check(File::open(&path).map_err(|e| e.to_string())?, listing)
        }
    })
    .with_ignored_flag(ignored)
    .with_kind(sample.format.to_lowercase())
}

/// Fixtures this crate reads differently from upstream, ignored until fixed, each with the bug it shows.
const KNOWN_BUGS: &[(&str, &str)] = &[];

/// Archives upstream wrote for cases the corpus lacks, each beside upstream's listing of it.
fn fixtures() -> Vec<Trial> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    let mut names: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "cfs"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no fixtures in {}", dir.display());
    for &(bug, _) in KNOWN_BUGS {
        assert!(
            names
                .iter()
                .any(|path| path.file_stem().is_some_and(|stem| stem == bug)),
            "KNOWN_BUGS names {bug}, which is not a fixture"
        );
    }

    names
        .into_iter()
        .map(|archive| {
            let name = archive
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let known_bug = KNOWN_BUGS.iter().any(|&(bug, _)| bug == name);
            Trial::test(name, move || {
                let listing = archive.with_extension("tsv");
                check(
                    fs::read(&archive).map_err(|e| e.to_string())?,
                    Some(&listing),
                )
            })
            .with_kind("fixture")
            .with_ignored_flag(known_bug)
        })
        .collect()
}

fn main() {
    let dir = samples_dir();
    let listings = oracle_dir().join("manifests");
    let mut trials: Vec<Trial> = manifest()
        .into_iter()
        .filter(|s| s.format != "none")
        .map(|s| trial(s, &dir, &listings))
        .collect();
    trials.extend(fixtures());
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}
