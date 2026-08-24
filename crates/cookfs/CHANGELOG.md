# Changelog

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
