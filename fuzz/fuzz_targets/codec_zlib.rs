//! Decodes arbitrary bytes as zlib's raw deflate, under a tight limit.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "codec.rs"]
mod codec;

fuzz_target!(|data: &[u8]| codec::run(1, data));
