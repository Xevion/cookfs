//! Entry names, decoded the way the Tcl runtime that wrote them reads them back.
//!
//! Tcl stores strings in a modified UTF-8 and reads bytes that are not UTF-8
//! leniently, so a name upstream lists can be invalid UTF-8 on disk. Matching
//! Tcl 8.6 character for character keeps distinct names distinct:
//!
//! - `C0 80` is NUL, which Tcl stores that way so its strings never hold a zero byte.
//! - A surrogate pair stored as two 3-byte sequences (CESU-8) is one character.
//! - Any other byte that does not start a valid sequence is its Latin-1 character.
//! - A raw zero byte ends the name, since upstream reads it as a C string.
//!
//! A lone surrogate has no Rust `char`, so it alone is lossy, as U+FFFD.

/// Decodes one stored name.
pub(crate) fn decode(stored: &[u8]) -> String {
    let stored = stored.split(|&b| b == 0).next().unwrap_or_default();
    let mut out = String::with_capacity(stored.len());
    let mut rest = stored;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(e) => {
                let (valid, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                rest = lenient(bad, &mut out);
            }
        }
    }
    out
}

const fn continuation(b: u8) -> bool {
    b & 0xC0 == 0x80
}

/// The code point of a 3-byte sequence, which for these callers is always a surrogate.
fn three(lead: u8, mid: u8, last: u8) -> u32 {
    (u32::from(lead & 0x0F) << 12) | (u32::from(mid & 0x3F) << 6) | u32::from(last & 0x3F)
}

/// Decodes the shape at the start of `bad`, which strict UTF-8 refused, and returns what follows it.
fn lenient<'a>(bad: &'a [u8], out: &mut String) -> &'a [u8] {
    match bad {
        [0xC0, 0x80, tail @ ..] => {
            out.push('\0');
            tail
        }
        [
            0xED,
            h1 @ 0xA0..=0xAF,
            h2,
            0xED,
            l1 @ 0xB0..=0xBF,
            l2,
            tail @ ..,
        ] if continuation(*h2) && continuation(*l2) => {
            let high = three(0xED, *h1, *h2) - 0xD800;
            let low = three(0xED, *l1, *l2) - 0xDC00;
            out.push(
                char::from_u32(0x10000 + (high << 10) + low).unwrap_or(char::REPLACEMENT_CHARACTER),
            );
            tail
        }
        [0xED, 0xA0..=0xBF, b, tail @ ..] if continuation(*b) => {
            out.push(char::REPLACEMENT_CHARACTER);
            tail
        }
        [b, tail @ ..] => {
            out.push(char::from(*b));
            tail
        }
        [] => bad,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use rstest::rstest;

    /// Each case's expectation is what upstream's Tcl holds for the same bytes.
    #[rstest]
    #[case::plain(b"plain.txt", "plain.txt")]
    #[case::tcl_nul(b"nul\xc0\x80byte", "nul\0byte")]
    #[case::raw_nul_ends_the_name(b"a\0b", "a")]
    #[case::latin1(b"x\xfey", "x\u{fe}y")]
    #[case::overlong_two(b"o\xc1\xbf", "o\u{c1}\u{bf}")]
    #[case::overlong_three(b"z\xe0\x80\x80", "z\u{e0}\u{80}\u{80}")]
    #[case::cesu_pair(b"p\xed\xa0\xbd\xed\xb8\x80", "p\u{1F600}")]
    #[case::four_byte(b"f\xf0\x9f\x98\x80", "f\u{1F600}")]
    #[case::lone_surrogate(b"s\xed\xa0\x80", "s\u{FFFD}")]
    #[case::truncated_at_end(b"h\xe2\x82", "h\u{e2}\u{82}")]
    #[case::truncated_before_ascii(b"i\xe2\x82x", "i\u{e2}\u{82}x")]
    #[case::stray_continuation(b"c\x80", "c\u{80}")]
    #[case::five_byte(b"g\xf8\x88\x80\x80\x80", "g\u{f8}\u{88}\u{80}\u{80}\u{80}")]
    fn names_decode_as_tcl_reads_them(#[case] stored: &[u8], #[case] want: &str) {
        check!(decode(stored) == want);
    }

    proptest::proptest! {
        #[test]
        fn a_valid_utf8_name_without_nul_is_unchanged(name in "[^\0]{0,64}") {
            proptest::prop_assert_eq!(decode(name.as_bytes()), name);
        }

        #[test]
        fn any_bytes_decode_to_at_most_one_char_per_byte(stored in proptest::collection::vec(proptest::num::u8::ANY, 0..64)) {
            proptest::prop_assert!(decode(&stored).chars().count() <= stored.len());
        }
    }
}
