//! Encrypted archives upstream wrote, opened without their password or with the wrong one.
//!
//! Reading them with the right password is checked against upstream's listing
//! with the other fixtures.

use std::path::Path;

use assert2::check;
use cookfs::{Archive, CodecError, EncryptionMode, Error, OpenOptions};
use rstest::rstest;

fn open(name: &str, opts: &OpenOptions) -> cookfs::Result<Archive<Vec<u8>>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{name}.cfs"));
    let buf = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Archive::open(buf, opts)
}

#[rstest]
#[case::file("v3-encrypt-file", EncryptionMode::FILE)]
#[case::key("v3-encrypt-key", EncryptionMode::KEY)]
#[case::key_index("v3-encrypt-key-index", EncryptionMode::KEY_INDEX)]
fn without_a_password_each_mode_is_refused_as_encrypted(
    #[case] name: &str,
    #[case] mode: EncryptionMode,
) {
    let got = open(name, &OpenOptions::default());
    check!(matches!(got, Err(Error::Encrypted { mode: m }) if m == mode));
}

/// A stored key carries a copy of its IV, so a wrong password shows before any page is read.
#[rstest]
#[case::key("v3-encrypt-key")]
#[case::key_index("v3-encrypt-key-index")]
fn a_wrong_password_for_a_stored_key_is_refused_at_open(#[case] name: &str) {
    let wrong = OpenOptions::default().with_password("hunter2");
    check!(let Err(Error::WrongPassword) = open(name, &wrong));
}

/// `FILE` mode stores no key to check, so a wrong password shows as pages that fail to decrypt.
#[test]
fn a_wrong_file_mode_password_fails_every_encrypted_read() {
    let wrong = OpenOptions::default().with_password("hunter2");
    let archive = open("v3-encrypt-file", &wrong).unwrap();
    let failures: Vec<_> = archive
        .walk()
        .filter(|&(_, idx)| archive.node(idx).size() > 0)
        .map(|(_, idx)| archive.read(idx))
        .collect();
    check!(!failures.is_empty());
    for got in failures {
        check!(let Err(Error::Decode { source: CodecError::Decrypt { .. } | CodecError::HashMismatch { .. }, .. }) = got);
    }
}
