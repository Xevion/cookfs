//! Opens arbitrary bytes as an archive and reads every file it lists.

#![no_main]

use cookfs::{Archive, Limits, OpenOptions};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut limits = Limits::default();
    limits.max_fsindex_len = 1 << 20;
    limits.max_page_len = 1 << 20;
    let mut opts = OpenOptions::default();
    opts.limits = limits;
    if let Ok(archive) = Archive::open(data.to_vec(), &opts) {
        for (_, idx) in archive.walk() {
            let _ = archive.read(idx);
        }
    }
});
