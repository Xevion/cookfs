use assert2::check;

use crate::parsers::{cfs0002, cfs0003};
use crate::wire::Compression;
use crate::{
    ArchiveVersion, Blob, DecodeError, Encryption, EncryptionMode, Error, Limits, TrailerError,
};
use kit::{
    Fsindex, archive_v2, archive_v3, crc_slot, digits_v2, one_file_v2, one_file_v3, open,
    open_unverified, open_with, stored, stored_page,
};

pub(crate) mod alloc;
mod bounds;
mod generated;
pub(crate) mod kit;
mod sweep;

#[test]
fn an_archive_reports_its_version_and_encryption() {
    let v2 = open(one_file_v2(b"hello world!")).unwrap();
    check!(v2.version() == ArchiveVersion::Cfs0002);
    check!(v2.encryption().is_none());

    let v3 = open(one_file_v3(b"hello v3!")).unwrap();
    check!(v3.version() == ArchiveVersion::Cfs0003);
    check!(
        v3.encryption()
            == Some(Encryption {
                mode: EncryptionMode::NONE,
                level: 15
            })
    );
}

#[test]
fn a_source_without_a_signature_is_refused() {
    check!(let Err(Error::Trailer { source: TrailerError::NoSignature }) = open(vec![0u8; 32]));
}

#[test]
fn a_block_naming_a_missing_page_is_refused_at_open() {
    let fsindex = Fsindex::new(1).file("f", &[(5, 0, 1)]).finish();
    let buf = archive_v2(&[], &stored(&fsindex));
    check!(let Err(Error::PageOutOfRange { page: 5, pages: 0 }) = open(buf));
}

/// Found by the `archive` fuzz target: blocks summing to 4 GiB reserved that much up front.
#[test]
fn a_file_claiming_gigabytes_is_refused_before_reading() {
    let fsindex = Fsindex::new(1)
        .file("f", &[(0, 0, i32::MAX), (0, 0, i32::MAX)])
        .finish();
    let archive = open(digits_v2(&fsindex)).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::FileTooLarge { size: 4_294_967_294, .. }) = archive.read(idx));
}

/// Many blocks over one page multiply the output without growing the archive.
#[test]
fn blocks_repeating_one_page_cannot_pass_the_file_limit() {
    let blocks = vec![(0, 0, 1000); 2000];
    let fsindex = Fsindex::new(1).file("f", &blocks).finish();
    let buf = archive_v2(&[stored_page(&[7; 1000])], &stored(&fsindex));
    let limits = Limits {
        max_file_len: 1 << 20,
        ..Limits::default()
    };
    let archive = open_with(buf, limits).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::FileTooLarge { size: 2_000_000, .. }) = archive.read(idx));
}

/// Blocks cycling through pages force a decode each; the read stops instead of thrashing.
#[test]
fn blocks_cycling_through_pages_stop_the_read() {
    let blocks: Vec<_> = (0..30).map(|i| (i % 3, 0, 1)).collect();
    let fsindex = Fsindex::new(1).file("f", &blocks).finish();
    let pages = [1, 2, 3].map(|b| stored_page(&[b; 1000]));
    let buf = archive_v2(&pages, &stored(&fsindex));
    let limits = Limits {
        max_page_len: 1000,
        ..Limits::default()
    };
    let archive = open_with(buf, limits).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::Overdecoded { size: 30, decoded: 3000 }) = archive.read(idx));
}

#[test]
fn a_file_revisiting_a_page_in_order_reads() {
    let fsindex = Fsindex::new(1)
        .file("f", &[(0, 0, 2), (1, 0, 2), (0, 2, 2)])
        .finish();
    let pages = [stored_page(b"abcd"), stored_page(b"wxyz")];
    let archive = open(archive_v2(&pages, &stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(archive.read(idx).unwrap() == b"abwxcd");
}

/// `KEY_INDEX` encrypts the pgindex, so the mode is checked before decoding it.
#[test]
fn a_key_index_archive_is_refused_as_encrypted_not_as_corrupt() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, 1)]).finish();
    let mut buf = archive_v3(&[vec![1]], &fsindex, 0x7B);
    let pgindex_codec = buf.len() - cfs0003::SIGNATURE.len() - 55 + 3;
    buf[pgindex_codec] = Compression::ZLIB.raw();
    check!(let Err(Error::Encrypted { mode: EncryptionMode::KEY_INDEX }) = open(buf));
}

/// A page the pgindex flags as encrypted is never handed back as plaintext.
#[test]
fn a_page_flagged_encrypted_is_refused() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, 3)]).finish();
    let mut buf = archive_v3(&[b"abc".to_vec()], &fsindex, 0x78);
    buf[3 + 4 + 2] = 1;
    let archive = open(buf).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::EncryptedPage { page: 0 }) = archive.read(idx));
}

/// A stored page whose bytes changed after its `crc32` slot was written.
#[test]
fn a_page_failing_its_hash_is_refused_unless_verification_is_off() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, 5)]).finish();
    let page = (stored(b"hellp"), crc_slot(b"hello"));
    let buf = archive_v2(&[page], &stored(&fsindex));

    let archive = open(buf.clone()).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::Decode { blob: Blob::Page(0), source: DecodeError::HashMismatch { hash: "CRC-32" } }) = archive.read(idx));

    let archive = open_unverified(buf).unwrap();
    check!(archive.read(idx).unwrap() == b"hellp");
}

/// Flipping one byte of every page or index blob in a real archive is caught by its MD5.
#[test]
fn a_corrupted_byte_in_an_upstream_archive_fails_its_md5() {
    // Pages start after upstream's 15-byte `CFSS003` stamp, which no hash covers.
    const STAMP: usize = 15;
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3-none.cfs");
    let clean = std::fs::read(fixture).unwrap();
    let read_all = |buf: Vec<u8>| -> crate::Result<()> {
        let archive = open(buf)?;
        for (_, idx) in archive.page_order() {
            archive.read(idx)?;
        }
        Ok(())
    };
    check!(read_all(clean.clone()).is_ok());
    let tail = clean.len() - cfs0003::SIGNATURE.len() - 55;
    let mut caught = 0;
    for at in (STAMP..tail).step_by(97) {
        let mut buf = clean.clone();
        buf[at] ^= 0x01;
        caught += usize::from(read_all(buf).is_err());
    }
    check!(caught == (tail - STAMP).div_ceil(97));
}

/// Two filesets at the root; the first written is active, as upstream activates a custom one.
fn two_filesets() -> crate::Archive<Vec<u8>> {
    let fsindex = Fsindex::new(2)
        .dir("zeta", 1)
        .file("z.txt", &[(0, 0, 1)])
        .dir("alpha", 1)
        .file("a.txt", &[(0, 1, 1)])
        .finish_with(&[b"cookfs.fileset\0custom"]);
    open(archive_v3(&[b"za".to_vec()], &fsindex, 0x78)).unwrap()
}

#[test]
fn a_fileset_archive_lists_the_first_written_fileset_as_its_root() {
    let archive = two_filesets();
    check!(archive.filesets() == ["alpha", "zeta"]);
    check!(archive.fileset() == Some("zeta"));
    let walked: Vec<String> = archive.walk().map(|(p, _)| p).collect();
    check!(walked == ["z.txt"]);
    check!(archive.metadata("cookfs.fileset") == Some(&b"custom"[..]));
}

#[test]
fn another_fileset_can_be_selected_and_a_missing_one_is_refused() {
    let mut archive = two_filesets();
    archive.select_fileset("alpha").unwrap();
    let (path, idx) = archive.walk().next().unwrap();
    check!(path == "a.txt");
    check!(archive.read(idx).unwrap() == b"a");
    check!(let Err(Error::NoSuchFileset { .. }) = archive.select_fileset("beta"));
    check!(archive.fileset() == Some("alpha"));
}

#[test]
fn without_fileset_metadata_root_directories_are_plain_directories() {
    let fsindex = Fsindex::new(1).dir("alpha", 0).finish();
    let archive = open(archive_v3(&[], &fsindex, 0x78)).unwrap();
    check!(archive.filesets().is_empty());
    check!(archive.fileset().is_none());
}

#[test]
fn names_that_could_escape_a_directory_are_not_portable() {
    let fsindex = Fsindex::new(6)
        .file("ok.txt", &[])
        .file("..", &[])
        .file(".", &[])
        .file("a/b", &[])
        .file("back\\slash", &[])
        .file("", &[])
        .finish();
    let archive = open(archive_v3(&[], &fsindex, 0x78)).unwrap();
    let portable: Vec<String> = archive
        .walk()
        .filter(|&(_, id)| archive.node(id).has_portable_name())
        .map(|(path, _)| path)
        .collect();
    check!(portable == ["ok.txt"]);

    let fsindex = Fsindex::new(1).dir("..", 1).file("inner", &[]).finish();
    let archive = open(archive_v3(&[], &fsindex, 0x78)).unwrap();
    let inner = archive.lookup("../inner").unwrap();
    check!(archive.node(inner).has_portable_name());
    check!(!archive.has_portable_path(inner));
}

/// A stray all-zero trailer before a damaged archive once opened as an empty one.
#[test]
fn a_decoy_trailer_does_not_stand_in_for_a_damaged_archive() {
    let mut buf = vec![0u8; 9];
    buf.extend_from_slice(cfs0002::SIGNATURE);
    let mut real = one_file_v2(b"hello");
    let count_at = real.len() - cfs0002::SIGNATURE.len() - 5;
    real[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    buf.extend(real);
    check!(let Err(Error::Trailer { source: TrailerError::NoSignature }) = open(buf));
}

/// Every hit used to run a full parse, so a file packed with signatures took hours to refuse.
#[test]
fn a_source_packed_with_signatures_is_refused_quickly() {
    let mut unit = [0u8; 16];
    unit[4..8].copy_from_slice(&1000u32.to_be_bytes());
    unit[9..].copy_from_slice(cfs0002::SIGNATURE);
    let buf = unit.repeat(1 << 18);
    let started = std::time::Instant::now();
    check!(open(buf).is_err());
    check!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn an_fsindex_over_the_limit_is_refused() {
    let limits = Limits {
        max_fsindex_len: 4,
        ..Limits::default()
    };
    let got = open_with(one_file_v2(b"x"), limits);
    check!(let Err(Error::Decode { blob: Blob::Fsindex, source: DecodeError::TooLarge { limit: 4, .. } }) = got);
}
