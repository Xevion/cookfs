//! Format-specific trailer parsers that each build a shared [`crate::page::Layout`].
//!
//! This is the only place a `CFS0002` vs `CFS0003` branch is allowed to fire.
//! Everything downstream of `Archive::open` reads the normalized [`crate::page::Layout`]
//! and never asks which format produced it.

pub mod cfs0002;
pub mod cfs0003;
