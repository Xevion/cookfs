//! Decodes arbitrary bytes as `CFS0003`'s raw LZMA1, which stops only at its declared size.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "codec.rs"]
mod codec;

fuzz_target!(|data: &[u8]| codec::run(3, data));
