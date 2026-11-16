//! The body every `codec_*` target shares: one codec, a tight output limit.
//!
//! Input is a big-endian `u32` declared size, `u32::MAX` for none, then the
//! payload. A decode must stay within the limit, match a declared size it
//! accepted, and decode the same bytes twice to the same output.

/// Small enough that an output bomb or an oversized allocation stands out.
pub const LIMIT: usize = 1 << 16;

pub fn run(id: u8, data: &[u8]) {
    let Some((declared, body)) = data.split_first_chunk::<4>() else {
        return;
    };
    let declared = match u32::from_be_bytes(*declared) {
        u32::MAX => None,
        n => Some(n as usize),
    };
    let first = cookfs::fuzzing::decode(id, body, declared, LIMIT);
    if let Ok(out) = &first {
        assert!(
            out.len() <= LIMIT,
            "{} bytes past the {LIMIT}-byte limit",
            out.len()
        );
        if let Some(want) = declared {
            assert_eq!(
                out.len(),
                want,
                "accepted output differs from its declared size"
            );
        }
    }
    let second = cookfs::fuzzing::decode(id, body, declared, LIMIT);
    assert_eq!(first.ok(), second.ok(), "one input decoded two ways");
}
