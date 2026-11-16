# Fuzzing

`tempo fuzz -- <target> [-- libfuzzer flags]`, for example
`tempo fuzz -- archive -- -max_total_time=300`. libFuzzer's default 2 GiB RSS cap turns an
allocator abort into a reported out-of-memory.

| Target | Feeds |
| --- | --- |
| `archive` | Whole files through `Archive::open`, then every file through `Archive::read` |
| `fsindex` | A decoded fsindex blob |
| `pgindex` | A decoded `CFS0003` pgindex blob |

