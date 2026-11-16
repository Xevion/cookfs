#!/usr/bin/env bun
//! Seeds every fuzz target's corpus from the fixtures upstream wrote.
//!
//! `bun run fuzz/seeds.ts` fills `fuzz/corpus/<target>/`: whole archives for
//! `archive`, decoded indexes for `fsindex` and `pgindex`, and each page body,
//! behind its declared size, for the `codec_*` target its codec belongs to.
//! Only fixtures whose last bytes are a signature are taken apart; the rest
//! still seed `archive`.

import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { brotliDecompressSync, inflateRawSync, zstdDecompressSync } from "node:zlib";

const ROOT = resolve(import.meta.dirname, "..");
const FIXTURES = join(ROOT, "crates", "cookfs", "tests", "fixtures");
const CORPUS = join(ROOT, "fuzz", "corpus");

/// The `codec_*` input header for no declared size.
const UNDECLARED = 0xffff_ffff;

const CODEC_TARGET: Record<number, string> = {
  1: "codec_zlib",
  2: "codec_bzip2",
  3: "codec_lzma",
  4: "codec_zstd",
  5: "codec_brotli",
  255: "codec_lzma_alone",
};

let written = 0;

function seed(target: string, name: string, data: Uint8Array): void {
  const dir = join(CORPUS, target);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), data);
  written += 1;
}

function codecSeed(id: number, name: string, declared: number, body: Uint8Array): void {
  const target = CODEC_TARGET[id];
  if (!target) return;
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, declared);
  out.set(body, 4);
  seed(target, name, out);
}

/// What a command writes to stdout given `input`, even when it exits complaining the input ended.
function pipe(cmd: string[], input: Uint8Array): Uint8Array {
  return Bun.spawnSync(cmd, { stdin: input, stdout: "pipe", stderr: "ignore" }).stdout;
}

/// A decoded index blob of `plain` bytes, or `undefined` for a codec this script does not undo.
function inflate(codec: number, blob: Uint8Array, plain: number): Uint8Array | undefined {
  switch (codec) {
    case 0:
      return blob;
    case 1:
      return inflateRawSync(blob);
    case 2:
      return pipe(["bzip2", "-dc"], blob);
    case 3: {
      // Raw LZMA1 has no end marker, so xz decodes what it can and stops at the input's end.
      const props = blob[0]!;
      const dict = new DataView(blob.buffer, blob.byteOffset + 1, 4).getUint32(0, true);
      const lzma1 = `lc=${props % 9},lp=${Math.floor(props / 9) % 5},pb=${Math.floor(props / 45)},dict=${dict}`;
      return pipe(["xz", "--format=raw", `--lzma1=${lzma1}`, "-dc"], blob.subarray(5)).subarray(0, plain);
    }
    case 4:
      return zstdDecompressSync(blob);
    case 5:
      return brotliDecompressSync(blob);
    default:
      return undefined;
  }
}

function endsWith(buf: Uint8Array, sig: string): boolean {
  return buf.length >= sig.length && new TextDecoder().decode(buf.subarray(buf.length - sig.length)) === sig;
}

function legacy(name: string, buf: Uint8Array): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const headAt = buf.length - 7 - 9;
  const fsindexLen = view.getUint32(headAt);
  const pages = view.getUint32(headAt + 4);
  const fsindexAt = headAt - fsindexLen;
  const sizesAt = fsindexAt - 4 * pages;
  const slotsAt = sizesAt - 16 * pages;
  const fsindex = buf.subarray(fsindexAt, headAt);
  // A legacy bzip2 blob carries its size ahead of the stream, and the custom slot is `.lzma`-alone.
  const [codec, body] = [fsindex[0], fsindex.subarray(fsindex[0] === 2 ? 5 : 1)];
  const index = codec === 255 ? pipe(["xz", "--format=lzma", "-dc"], body) : inflate(codec ?? -1, body, 0);
  if (index && index.length > 0) seed("fsindex", `${name}.fsindex`, index);

  const sizes = Array.from({ length: pages }, (_, i) => view.getUint32(sizesAt + 4 * i));
  let at = slotsAt - sizes.reduce((a, b) => a + b, 0);
  sizes.forEach((size, i) => {
    const blob = buf.subarray(at, at + size);
    at += size;
    const slot = buf.subarray(slotsAt + 16 * i, slotsAt + 16 * i + 16);
    const crcMode = slot.subarray(0, 8).every((b) => b === 0) && slot.some((b) => b !== 0);
    const declared = crcMode ? new DataView(slot.buffer, slot.byteOffset + 8, 4).getUint32(0) : UNDECLARED;
    if (blob[0] === 2) {
      const prefix = new DataView(blob.buffer, blob.byteOffset + 1, 4).getUint32(0);
      codecSeed(2, `${name}.page${i}`, prefix, blob.subarray(5));
    } else if (blob.length > 0) {
      codecSeed(blob[0]!, `${name}.page${i}`, declared, blob.subarray(1));
    }
  });
}

function current(name: string, buf: Uint8Array): void {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const suffixAt = buf.length - 7 - 55;
  const info = (at: number) => ({
    codec: buf[at]!,
    stored: view.getUint32(at + 18),
    plain: view.getUint32(at + 22),
  });
  const pg = info(suffixAt + 3);
  const fs = info(suffixAt + 29);
  const fsindexAt = suffixAt - fs.stored;
  const pgindexAt = fsindexAt - pg.stored;
  const index = inflate(fs.codec, buf.subarray(fsindexAt, suffixAt), fs.plain);
  if (index && index.length > 0) seed("fsindex", `${name}.fsindex`, index);
  const table = inflate(pg.codec, buf.subarray(pgindexAt, fsindexAt), pg.plain);
  if (!table || table.length < 4) return;
  seed("pgindex", `${name}.pgindex`, table);

  const tv = new DataView(table.buffer, table.byteOffset, table.byteLength);
  const n = tv.getUint32(0);
  const stored = (i: number) => tv.getUint32(4 + 3 * n + 4 * i);
  const plain = (i: number) => tv.getUint32(4 + 7 * n + 4 * i);
  let at = pgindexAt - Array.from({ length: n }, (_, i) => stored(i)).reduce((a, b) => a + b, 0);
  for (let i = 0; i < n; i++) {
    codecSeed(table[4 + i]!, `${name}.page${i}`, plain(i), buf.subarray(at, at + stored(i)));
    at += stored(i);
  }
}

for (const dir of [FIXTURES, join(FIXTURES, "unlisted")]) {
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".cfs")).sort()) {
    const path = join(dir, file);
    const name = basename(file, ".cfs");
    mkdirSync(join(CORPUS, "archive"), { recursive: true });
    copyFileSync(path, join(CORPUS, "archive", file));
    written += 1;
    const buf = new Uint8Array(readFileSync(path));
    try {
      if (endsWith(buf, "CFS0002")) legacy(name, buf);
      else if (endsWith(buf, "CFS0003")) current(name, buf);
    } catch (e) {
      console.error(`${file}: seeds the archive target only, its trailer does not decode: ${e}`);
    }
  }
}
console.log(`seeds: ${written} files under ${CORPUS}`);
