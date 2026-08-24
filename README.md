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

## License

MIT
