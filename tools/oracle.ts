#!/usr/bin/env bun
//! The differential oracle: upstream cookfs, built from pinned sources against the system Tcl.
//!
//! `CFS0002` is read by the 2015 tree (the legacy format current upstream no longer reads) and
//! `CFS0003` by the current one. `dump` lists every entry of every corpus sample as upstream
//! reads it, and the `oracle` test diffs this crate's reads against those listings.

import { mkdir, readdir, rename, rm } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const DIR = process.env.COOKFS_ORACLE_DIR ?? join(ROOT, "target", "oracle");
const SAMPLES = process.env.COOKFS_CORPUS_DIR ?? join(ROOT, "samples");
const DUMP = join(ROOT, "tools", "oracle", "dump.tcl");

type Flavor = "legacy" | "current";

/// Pinned so a listing never moves under the tree; bump deliberately, then re-run `dump`.
const TREES: Record<Flavor, { repo: string; rev: string; submodules: string[]; configure: string[] }> = {
  legacy: {
    repo: "https://github.com/greyltc/tcl-cookfs",
    rev: "f367cfe5f7e723369ef0d8ccc1898c0c30278b2e",
    submodules: [],
    // The 2015 sources declare nothing before use and use K&R definitions; newer gcc rejects both.
    configure: [
      "--enable-bz2",
      "--enable-threads",
      "--enable-64bit",
      "CC=cc -std=gnu99 -Wno-implicit-function-declaration",
    ],
  },
  current: {
    repo: "https://github.com/chpock/cookfs",
    rev: "04cdefa82c861f9ef09028415ff064ccb33c200f",
    submodules: ["tclconfig", "7zip", "zstd", "brotli"],
    configure: ["--enable-bz2", "--enable-zstd", "--enable-brotli", "--enable-64bit"],
  },
};

/// Upstream reads the largest sample in well under a minute; past this, a run is stuck, not slow.
const SAMPLE_TIMEOUT_MS = 5 * 60_000;

const FLAVOR_OF: Record<string, Flavor> = { CFS0002: "legacy", CFS0003: "current" };

type Sample = { name: string; format: string; container: "raw" | "zip" };

function die(message: string): never {
  console.error(`oracle: ${message}`);
  process.exit(1);
}

async function run(cmd: string[], cwd: string): Promise<void> {
  const proc = Bun.spawn(cmd, { cwd, stdout: "inherit", stderr: "inherit" });
  if ((await proc.exited) !== 0) die(`\`${cmd.join(" ")}\` failed in ${cwd}`);
}

async function output(cmd: string[], cwd = ROOT): Promise<string> {
  const proc = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "inherit" });
  const text = await new Response(proc.stdout).text();
  if ((await proc.exited) !== 0) die(`\`${cmd.join(" ")}\` failed`);
  return text;
}

async function tclConfigDir(): Promise<string> {
  const candidates = [
    process.env.TCL_CONFIG_DIR,
    "/usr/lib/tcl8.6",
    "/usr/lib/x86_64-linux-gnu/tcl8.6",
    "/usr/lib64",
    "/opt/homebrew/lib",
    "/usr/local/lib",
  ].filter((d): d is string => !!d);
  for (const dir of candidates) {
    if (await Bun.file(join(dir, "tclConfig.sh")).exists()) return dir;
  }
  die("no tclConfig.sh found; install Tcl's development files or set TCL_CONFIG_DIR");
}

async function library(flavor: Flavor): Promise<string> {
  const build = join(DIR, "build", flavor);
  const libs = (await readdir(build).catch(() => [] as string[])).filter(
    (f) => f.startsWith("libcookfs") && f.endsWith(".so"),
  );
  if (libs.length !== 1) die(`no ${flavor} build in ${build}; run \`tempo oracle -- build\``);
  return join(build, libs[0]!);
}

async function build(): Promise<void> {
  const tcl = await tclConfigDir();
  for (const [flavor, tree] of Object.entries(TREES) as [Flavor, (typeof TREES)[Flavor]][]) {
    const src = join(DIR, "src", flavor);
    const out = join(DIR, "build", flavor);
    const stamp = join(out, ".rev");
    if ((await Bun.file(stamp).exists()) && (await Bun.file(stamp).text()) === tree.rev) {
      console.log(`${flavor}: built at ${tree.rev.slice(0, 12)}`);
      continue;
    }

    await rm(src, { recursive: true, force: true });
    await rm(out, { recursive: true, force: true });
    await mkdir(src, { recursive: true });
    await mkdir(out, { recursive: true });
    await run(["git", "init", "-q"], src);
    await run(["git", "fetch", "-q", "--depth", "1", tree.repo, tree.rev], src);
    await run(["git", "checkout", "-q", "FETCH_HEAD"], src);
    if (tree.submodules.length > 0) {
      await run(["git", "remote", "add", "origin", tree.repo], src);
      await run(["git", "submodule", "update", "-q", "--init", "--depth", "1", ...tree.submodules], src);
    }

    await run([join(src, "configure"), `--with-tcl=${tcl}`, ...tree.configure], out);
    await run(["make", `-j${availableParallelism()}`], out);
    await Bun.write(stamp, tree.rev);
    console.log(`${flavor}: built ${await library(flavor)}`);
  }
}

async function load(): Promise<Sample[]> {
  const parsed = Bun.TOML.parse(await Bun.file(join(ROOT, "corpus.toml")).text()) as { sample?: Sample[] };
  return (parsed.sample ?? []).filter((s) => s.format in FLAVOR_OF);
}

/// The largest file under a `.app` bundle's `Contents/`, which is the binary the archive rides on.
async function extract(sample: Sample): Promise<string> {
  const zip = join(SAMPLES, sample.name);
  const listing = await output(["unzip", "-Z", "-l", zip]);
  let best: { name: string; size: number } | undefined;
  for (const line of listing.split("\n")) {
    const fields = line.trim().split(/\s+/);
    const name = fields.slice(9).join(" ");
    const size = Number(fields[3]);
    if (!line.startsWith("-") || !name.includes("/Contents/") || Number.isNaN(size)) continue;
    if (!best || size > best.size) best = { name, size };
  }
  if (!best) die(`${sample.name}: no file under /Contents/`);

  const path = join(DIR, "extracted", sample.name);
  await mkdir(join(DIR, "extracted"), { recursive: true });
  const proc = Bun.spawn(["unzip", "-p", zip, best.name], { stdout: Bun.file(path), stderr: "inherit" });
  if ((await proc.exited) !== 0) die(`${sample.name}: could not extract ${best.name}`);
  return path;
}

async function dumpOne(sample: Sample, libs: Record<Flavor, string>): Promise<boolean> {
  const flavor = FLAVOR_OF[sample.format]!;
  const archive = sample.container === "zip" ? await extract(sample) : join(SAMPLES, sample.name);
  const out = join(DIR, "manifests", `${sample.name}.tsv`);
  const partial = `${out}.partial`;

  const proc = Bun.spawn(["tclsh", DUMP, flavor, libs[flavor], archive], {
    stdout: Bun.file(partial),
    stderr: "pipe",
    timeout: SAMPLE_TIMEOUT_MS,
  });
  const stderr = await new Response(proc.stderr).text();
  if ((await proc.exited) !== 0) {
    await rm(partial, { force: true });
    const why = proc.signalCode ? `killed by ${proc.signalCode} after ${SAMPLE_TIMEOUT_MS / 1000}s` : "failed";
    console.error(`${sample.name}: upstream ${why}\n${stderr}`);
    return false;
  }
  await rename(partial, out);
  const lines = (await Bun.file(out).text()).split("\n").length - 1;
  console.log(`${sample.name}: ${lines} entries`);
  return true;
}

async function dump(args: string[]): Promise<void> {
  const libs = { legacy: await library("legacy"), current: await library("current") };
  const wanted = new Set(args);
  const samples = (await load()).filter((s) => wanted.size === 0 || wanted.has(s.name));
  const missing = [];
  for (const s of samples) {
    if (!(await Bun.file(join(SAMPLES, s.name)).exists())) missing.push(s.name);
  }
  if (missing.length > 0) die(`samples not fetched: ${missing.join(", ")}; run \`tempo corpus -- pull\``);

  await mkdir(join(DIR, "manifests"), { recursive: true });
  const jobs = Math.max(1, Math.min(availableParallelism(), 8));
  let next = 0;
  let failed = 0;
  await Promise.all(
    Array.from({ length: jobs }, async () => {
      for (let i = next++; i < samples.length; i = next++) {
        if (!(await dumpOne(samples[i]!, libs))) failed += 1;
      }
    }),
  );
  if (failed > 0) die(`${failed} of ${samples.length} samples failed`);
}

const USAGE = `oracle <command>

  build             fetch and build both pinned upstream trees under target/oracle
  dump [sample...]  list every corpus sample (or the named ones) as upstream reads it`;

const [command = "help", ...rest] = process.argv.slice(2);
switch (command) {
  case "build":
    await build();
    break;
  case "dump":
    await dump(rest);
    break;
  default:
    console.log(USAGE);
    process.exit(command === "help" || command === "--help" ? 0 : 1);
}
