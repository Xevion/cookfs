# Changelog

## [Unreleased]

## [0.2.1] - 2026-11-16

### Changed

- `CodecError` is renamed `DecodeError`, since it covers decryption and hash checks as well as
  codecs.
- zlib and LZMA pages decode straight into their output, skipping the doubling and zero-fill
  of a read loop, and cached pages are no longer copied on the way in. Extracting the largest
  sample installer takes about 15% less time and 8% less memory.

## [0.2.0] - 2026-11-16

### Breaking

- Nodes are named by an opaque `NodeId` instead of a re-exported `la_arena::Idx`.
- `Archive::walk` returns a lazy `Walk` iterator that builds one path at a time, instead of a
  `Vec` holding every path at once.
- `Archive::read` on a directory is `Error::NotAFile` instead of an empty `Vec`.
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
- `OpenOptions` is `Clone` but no longer `Copy`, since it can hold a password.
- `Error::Encrypted` now means no password was given.
- `Limits` gains `max_file_len` (1 GiB by default), past which `Archive::read` refuses a file.
- A directory's children are sorted by name.

### Added

- Every page, pgindex and fsindex is checked against the MD5 or CRC-32 the archive stores for
  it, failing with `CodecError::HashMismatch`. On by default; `OpenOptions::verify` turns it
  off. Blobs written without a hash are not checked.
- Encrypted `CFS0003` archives read with `OpenOptions::with_password`, in all three of
  upstream's modes. A `KEY` or `KEY_INDEX` archive opened with the wrong password fails with
  `Error::WrongPassword`; a `FILE` one fails as its pages fail to decrypt.
- `Archive::open_file` streams a file as `Read + Seek`, decoding pages only as it reaches
  them and without `read`'s size limit.
- `Archive::lookup` finds an entry by path, `Archive::page_order` lists files in the order
  their data sits so each page decodes about once, and `Archive::root` is the directory
  paths start from.
- `Node::has_portable_name` and `Archive::has_portable_path` say whether a name or path is
  safe to create on disk; upstream stores names such as `..` and ones holding `/`.
- `Archive::metadata` and `Archive::metadata_entries` read the fsindex's archive-wide records.
- Fileset archives list their active fileset as the root, as upstream mounts them.
  `Archive::filesets`, `Archive::fileset` and `Archive::select_fileset` list and switch them.

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
- A deeply nested fsindex can no longer overflow the stack.
- A crafted LZMA dictionary size or file size can no longer force a multi-GiB allocation.
- A source packed with signatures is refused quickly; each hit was a full trailer parse.
- A stray all-zero trailer no longer opens as an empty archive in place of a damaged one.
- A decoy trailer after the archive that fails to open no longer hides the real one; when
  no candidate opens, the error is the rightmost candidate's, not `NoSignature`.
- The page cache is bounded by decoded bytes, not page count, so pages that decode far larger
  than their compressed size cannot hold gigabytes resident.
- A file whose blocks cycle through pages stops with `Error::Overdecoded` instead of
  decoding a page per block.
- Nested directory counts no longer reserve memory the blob cannot fill.
- A page the pgindex flags as encrypted, in an archive holding no key, is refused instead of
  returned as ciphertext.
- A name repeated in one directory keeps its last entry, as upstream does, and a file and
  directory sharing a name are refused.
- Names decode as the Tcl runtime that wrote them reads them: `C0 80` is NUL, a CESU-8
  surrogate pair is one character, a byte that is not UTF-8 is its Latin-1 character, and a
  raw NUL ends the name. Distinct names that once all read as U+FFFD stay distinct.
- An fsindex with no metadata section, as archives before 2011 have, parses.
- Bytes after the last pgindex record are refused, as upstream does.
- A blob naming a codec its format cannot hold is refused: zstd or brotli in `CFS0002`,
  BitRock's LZMA slot in `CFS0003`.
- A `CFS0003` page declared empty is empty without decoding.
- A zstd frame can no longer make the decoder allocate a window larger than the output it
  may produce, and large-window brotli, which upstream refuses, is refused.

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
