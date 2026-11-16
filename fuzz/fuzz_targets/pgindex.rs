//! Parses arbitrary bytes as a decoded `CFS0003` pgindex.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cookfs::fuzzing::pgindex(data));
