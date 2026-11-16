//! Decodes arbitrary bytes as the legacy custom slot's `.lzma`-alone stream, under a tight limit.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "codec.rs"]
mod codec;

fuzz_target!(|data: &[u8]| codec::run(255, data));
