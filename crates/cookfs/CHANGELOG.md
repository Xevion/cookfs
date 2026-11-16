# Changelog

## [Unreleased]

### Breaking

- `Archive::open` takes `&OpenOptions`, and `open_with` is gone. Size ceilings live in
  `Limits`, which adds a page-size and a directory-depth ceiling to the fsindex one.
- `Codec` is replaced by `Compression`, which keeps an unknown id's number instead of
  failing to parse it.
- `Archive::encryption` returns an `Encryption` with a typed mode and level instead of the
  raw byte.
- Errors are split per layer (`SourceError`, `TrailerError`, `IndexError`, `CodecError`),
  with `Error` wrapping them.
- `Block` fields are unsigned.
- The `cache` module, `PageCache`, `Budget` and `Page` are no longer public.
- The public error enums, `Kind`, `ArchiveVersion`, `Blob`, `Node` and `Block` are
  `#[non_exhaustive]`.
- `Limits` gains `max_file_len` (1 GiB by default), past which `Archive::read` refuses a file.
- A directory's children are sorted by name.

### Fixed

- A `CFS0002` archive written in the default `md5` hash mode reads correctly. Its hash slots
  were read as `crc32`-mode sizes, which only that mode records.
- A `CFS0002` bzip2 blob decodes; legacy writes its size ahead of the stream.
- An empty file in a `CFS0003` archive, which upstream stores as a zero-size block on page -1,
  reads as empty instead of failing.
- A negative block field, or a block naming a page the archive lacks, is refused at open
  instead of at read.
- A block running past its page is an error instead of a silently short read.
- A decoded page or index that disagrees with its declared size is an error.
- An encrypted `CFS0003` archive is refused instead of read as garbage.
- A deeply nested fsindex can no longer overflow the stack.
- A crafted LZMA dictionary size or file size can no longer force a multi-GiB allocation.
- A source packed with signatures is refused quickly; each hit was a full trailer parse.
- A stray all-zero trailer no longer opens as an empty archive in place of a damaged one.
- The page cache is bounded by decoded bytes, not page count, so pages that decode far larger
  than their compressed size cannot hold gigabytes resident.
- A file whose blocks cycle through pages stops with `Error::Overdecoded` instead of
  decoding a page per block.
- Nested directory counts no longer reserve memory the blob cannot fill.
- A `KEY_INDEX` archive is reported as `Error::Encrypted`, not as a corrupt pgindex.
- A page the pgindex flags as encrypted is refused instead of returned as plaintext.
- A name repeated in one directory keeps its last entry, as upstream does, and a file and
  directory sharing a name are refused.
- An fsindex with no metadata section, as archives before 2011 have, parses.
- Bytes after the last pgindex record are refused, as upstream does.
- A blob naming a codec its format cannot hold is refused: zstd or brotli in `CFS0002`,
  BitRock's LZMA slot in `CFS0003`.
- A `CFS0003` page declared empty is empty without decoding.
- A zstd frame can no longer make the decoder allocate a window larger than the output it
  may produce, and large-window brotli, which upstream refuses, is refused.
- `Limits::max_depth` admits that many nested directories; it allowed one fewer.

## 0.1.0 (2026-08-24)


### Features

* **cache:** Add bounded LRU page cache ([5f193c4](https://github.com/Xevion/cookfs/commit/5f193c4a21455d63b43e8181931239bfa1a35a73))
* **codec:** Add bzip2, zstd, and brotli decoding ([e794c2b](https://github.com/Xevion/cookfs/commit/e794c2b8223f0d636d775064930c448b019e5a19))
* **codec:** Guard decompression against bomb inflation ([4f6cd30](https://github.com/Xevion/cookfs/commit/4f6cd301fb81d22d1299bc595405062d63c05338))
* **read:** Add archive reading for CFS0002 and CFS0003 formats ([541a928](https://github.com/Xevion/cookfs/commit/541a9283c9fbd39a014025d866a1a6fb3e0ef4b9))


### Code Refactoring

* Split into cookfs, metakit, and bitrock workspace crates ([955149d](https://github.com/Xevion/cookfs/commit/955149d0a14b7d1f84da409e2841b394b1479409))


### Continuous Integration

* Add release-please and crates.io publish workflows ([b347a4d](https://github.com/Xevion/cookfs/commit/b347a4d115b508db7fa56167c2ca2e26f53a233c))


### Miscellaneous

* Add CI/CD pipeline and testing infrastructure ([a9181f8](https://github.com/Xevion/cookfs/commit/a9181f82d35fa87f97726dbf1c60b2739f82ada0))
* Replace Justfile and corpus S3 action with tempo and TS tooling ([9e75e54](https://github.com/Xevion/cookfs/commit/9e75e5441defd06709aac4ba2a0ea460f564e63c))
