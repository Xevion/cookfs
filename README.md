# cookfs

A Rust implementation of [cookfs](https://wiki.tcl-lang.org/page/cookfs), the page-based
virtual filesystem archive format from the Tcl world.

A cookfs archive stores its payload as independently compressed pages, with a separate
index tree mapping each file onto the page ranges holding its content. Archives are
usually appended to a native stub binary rather than standing alone: tclkit does this to
carry a Tcl application's scripts, and BitRock/InstallBuilder installers do it to carry
everything the install lays down.

Version 0.0.0 carries no API. Development is tracked on the repository's `master` branch.

## License

MIT
