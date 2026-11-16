# Fuzzing

`tempo fuzz -- <target> [-- libfuzzer flags]`, for example
`tempo fuzz -- archive -- -max_total_time=300`. libFuzzer's default 2 GiB RSS cap turns an
allocator abort into a reported out-of-memory.

| Target | Feeds |
| --- | --- |
| `archive` | Whole files through `Archive::open`, then every file through `Archive::read` |
| `fsindex` | A decoded fsindex blob |
| `pgindex` | A decoded `CFS0003` pgindex blob |

## Aborts found

- `Archive::read` reserved a file's size before checking its blocks, and that size is a sum
  the fsindex supplies. Blocks summing to 4 GiB reserved 4 GiB.
- An LZMA header's dictionary size was allocated as declared. A crafted 45-byte archive
  asked for 4 GiB. Dictionary sizes are now clamped to the output limit, which no valid
  stream can tell apart.
