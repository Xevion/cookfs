//! Parses arbitrary bytes as a decoded fsindex.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| cookfs::fuzzing::fsindex(data));
