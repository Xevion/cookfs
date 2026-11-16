# cookfs

[![CI](https://github.com/Xevion/cookfs/actions/workflows/ci.yml/badge.svg)](https://github.com/Xevion/cookfs/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Xevion/cookfs/branch/master/graph/badge.svg)](https://codecov.io/gh/Xevion/cookfs)
[![crates.io](https://img.shields.io/crates/v/cookfs.svg)](https://crates.io/crates/cookfs)
[![docs.rs](https://img.shields.io/docsrs/cookfs)](https://docs.rs/cookfs)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Readers for the layered formats behind BitRock / VMware InstallBuilder installers and Tcl
starkits.

| Crate | Reads |
| --- | --- |
| [`cookfs`](crates/cookfs) | The archive holding the payload |
| [`metakit`](crates/metakit) | The database holding the bootstrap and manifest |
| [`bitrock`](crates/bitrock) | The installer, composing both |

`metakit` and `bitrock` are placeholders for now; `cookfs` is the one that reads anything.

## Development

Tasks run through [tempo](https://github.com/Xevion/tempo). `tempo check` is the gate: formatting,
clippy, docs, tests, licences, unused dependencies and workflow lints.

The tests check every archive against what upstream Tcl cookfs reads from it. The fixtures in
`crates/cookfs/tests/fixtures` are checked in; the corpus of real installers is not:

- `tempo corpus -- pull` fetches the corpus listed in `corpus.toml` (needs the `S3_*` values in
  `.env`). Without it, the corpus tests skip.
- `tempo oracle -- build` builds upstream cookfs, and `tempo oracle -- dump` lists the corpus
  through it. `tempo oracle -- fixtures` regenerates the fixtures (needs Tcl).
- `tempo fuzz -- <target>` runs a fuzz target; see `fuzz/README.md`.

## License

MIT
