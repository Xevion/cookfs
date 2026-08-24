//! cookfs, the page-based Tcl virtual filesystem archive format.
//!
//! A cookfs archive stores its payload as independently compressed pages, with
//! a separate index tree mapping each file onto the page ranges holding its
//! content. Archives are typically appended to a native stub binary rather than
//! standing alone: tclkit does this to carry a Tcl application's scripts, and
//! BitRock/InstallBuilder installers do it to carry everything the install lays
//! down.
