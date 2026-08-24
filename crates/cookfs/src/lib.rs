//! cookfs, the page-based Tcl virtual filesystem archive format.

pub mod cache;

pub use cache::{Budget, Page, PageCache};
