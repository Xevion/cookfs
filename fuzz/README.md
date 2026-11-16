# Fuzzing

`tempo fuzz -- <target> [-- libfuzzer flags]`, for example
`tempo fuzz -- archive -- -max_total_time=300 -dict=cookfs.dict`. libFuzzer's default 2 GiB RSS
cap turns an allocator abort into a reported out-of-memory; the codec targets are worth running
with `-malloc_limit_mb=64` as well, since their output limit is 64 KiB and any single allocation
near that cap is the decoder trusting a size from its input.

| Target | Feeds |
| --- | --- |
| `archive` | Whole files through `Archive::open`, then every file through `Archive::read` |
| `structured` | An arbitrary archive description, built as both `CFS0002` and `CFS0003` |
| `fsindex` | A decoded fsindex blob |
| `pgindex` | A decoded `CFS0003` pgindex blob |
| `codec_zlib`, `codec_bzip2`, `codec_lzma`, `codec_lzma_alone`, `codec_zstd`, `codec_brotli` | One codec's payload, behind a big-endian `u32` declared size (`u32::MAX` for none) |

`structured` holds a well-formed description (blocks inside their pages, honest counts, unique
UTF-8 names) to its one right reading in both formats, so a wrong read is a crash there, not only
a panic. The codec targets check that output stays under the limit, matches a declared size it was
accepted against, and decodes the same way twice.

## Seeds and dictionary

`bun run fuzz/seeds.ts` fills `fuzz/corpus/<target>/` from the fixtures upstream wrote: each
archive, its decoded fsindex and pgindex, and each page body under the codec target it belongs to.
The corpus is regenerated, not committed. `cookfs.dict` holds the signatures, the fsindex magic,
codec ids and stream headers, and the counts and sizes at their edges.

## Aborts found

- `Archive::read` reserved a file's size before checking its blocks, and that size is a sum
  the fsindex supplies. Blocks summing to 4 GiB reserved 4 GiB.
- An LZMA header's dictionary size was allocated as declared. A crafted 45-byte archive
  asked for 4 GiB. Dictionary sizes are now clamped to the output limit, which no valid
  stream can tell apart.
- A zstd frame's window is allocated as declared, up to the decoder's 128 MiB default, whatever
  the output limit. `codec_zstd` found a 14-byte payload asking for 64 MiB under a 64 KiB limit.
- A brotli stream's ring buffer is allocated for its whole window, and the decoder accepts the
  large-window format. `codec_brotli` found a 123-byte stream asking for 512 MiB under a 64 KiB
  limit.
