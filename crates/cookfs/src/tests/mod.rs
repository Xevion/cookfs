use assert2::check;

use crate::index::tests::Fsindex;
use crate::parsers::{cfs0002, cfs0003};
use crate::wire::Compression;
use crate::{
    Archive, ArchiveVersion, Blob, DecodeError, Encryption, EncryptionMode, Error, Kind, Limits,
    OpenOptions, Result, TrailerError,
};

mod hostile;

/// A stored `CFS0002` blob: id byte 0, then the payload.
fn stored(payload: &[u8]) -> Vec<u8> {
    let mut blob = vec![0u8];
    blob.extend_from_slice(payload);
    blob
}

fn open(buf: Vec<u8>) -> Result<Archive<Vec<u8>>> {
    Archive::open(buf, &OpenOptions::default())
}

/// One file, `hello.txt`, holding `payload` in page 0.
fn one_file_v2(payload: &[u8]) -> Vec<u8> {
    let fsindex = Fsindex::new(1)
        .file("hello.txt", &[(0, 0, payload.len() as i32)])
        .finish();
    let page = (stored(payload), cfs0002::tests::crc_slot(payload));
    cfs0002::tests::archive(&[page], &stored(&fsindex))
}

fn one_file_v3(payload: &[u8]) -> Vec<u8> {
    let fsindex = Fsindex::new(1)
        .file("hello.txt", &[(0, 0, payload.len() as i32)])
        .finish();
    cfs0003::tests::archive(&[payload.to_vec()], &fsindex, 0x78)
}

#[test]
fn a_cfs0002_file_reads_back_its_bytes() {
    let archive = open(one_file_v2(b"hello world!")).unwrap();
    check!(archive.version() == ArchiveVersion::Cfs0002);
    check!(archive.encryption().is_none());
    let (path, idx) = archive.walk().next().unwrap();
    check!(path == "hello.txt");
    check!(archive.read(idx).unwrap() == b"hello world!");
}

#[test]
fn a_cfs0003_file_reads_back_its_bytes() {
    let archive = open(one_file_v3(b"hello v3!")).unwrap();
    check!(archive.version() == ArchiveVersion::Cfs0003);
    check!(
        archive.encryption()
            == Some(Encryption {
                mode: EncryptionMode::NONE,
                level: 15
            })
    );
    let (_, idx) = archive.walk().next().unwrap();
    check!(archive.read(idx).unwrap() == b"hello v3!");
}

#[test]
fn an_encrypted_cfs0003_archive_is_refused_rather_than_misread() {
    let fsindex = Fsindex::new(0).finish();
    let buf = cfs0003::tests::archive(&[], &fsindex, 0x79);
    check!(let Err(Error::Encrypted { mode: EncryptionMode::FILE }) = open(buf));
}

#[test]
fn a_source_without_a_signature_is_refused() {
    check!(let Err(Error::Trailer { source: TrailerError::NoSignature }) = open(vec![0u8; 32]));
}

#[test]
fn a_block_naming_a_missing_page_is_refused_at_open() {
    let fsindex = Fsindex::new(1).file("f", &[(5, 0, 1)]).finish();
    let buf = cfs0002::tests::archive(&[], &stored(&fsindex));
    check!(let Err(Error::PageOutOfRange { page: 5, pages: 0 }) = open(buf));
}

#[test]
fn a_block_running_past_its_page_is_an_error() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 8, 9)]).finish();
    let page = (
        stored(b"0123456789"),
        cfs0002::tests::crc_slot(b"0123456789"),
    );
    let archive = open(cfs0002::tests::archive(&[page], &stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::BlockOutOfPage { page: 0, page_len: 10, .. }) = archive.read(idx));
}

/// Opens `buf` and reads every file, discarding the outcome; only a panic fails.
fn exercise(buf: Vec<u8>) {
    let opts = OpenOptions {
        limits: Limits {
            max_fsindex_len: 1 << 16,
            max_page_len: 1 << 16,
            max_file_len: 1 << 20,
            max_depth: 16,
        },
        ..OpenOptions::default()
    };
    if let Ok(archive) = Archive::open(buf, &opts) {
        for (_, idx) in archive.walk() {
            let _ = archive.read(idx);
        }
    }
}

mod robustness {
    use super::*;
    use proptest::prelude::*;

    fn mutated(base: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
        let len = base.len();
        proptest::collection::vec((0..len, any::<u8>()), 1..8).prop_map(move |edits| {
            let mut buf = base.clone();
            for (at, byte) in edits {
                buf[at] = byte;
            }
            buf
        })
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
            exercise(buf);
        }

        #[test]
        fn a_corrupted_cfs0002_archive_never_panics(buf in mutated(one_file_v2(b"hello world!"))) {
            exercise(buf);
        }

        #[test]
        fn a_corrupted_cfs0003_archive_never_panics(buf in mutated(one_file_v3(b"hello v3!"))) {
            exercise(buf);
        }
    }
}

/// Found by the `archive` fuzz target: blocks summing to 4 GiB reserved that much up front.
#[test]
fn a_file_claiming_gigabytes_is_refused_before_reading() {
    let fsindex = Fsindex::new(1)
        .file("f", &[(0, 0, i32::MAX), (0, 0, i32::MAX)])
        .finish();
    let page = (
        stored(b"0123456789"),
        cfs0002::tests::crc_slot(b"0123456789"),
    );
    let archive = open(cfs0002::tests::archive(&[page], &stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::FileTooLarge { size: 4_294_967_294, .. }) = archive.read(idx));
}

/// Many blocks over one page multiply the output without growing the archive.
#[test]
fn blocks_repeating_one_page_cannot_pass_the_file_limit() {
    let blocks = vec![(0, 0, 1000); 2000];
    let fsindex = Fsindex::new(1).file("f", &blocks).finish();
    let page = (stored(&[7; 1000]), cfs0002::tests::crc_slot(&[7; 1000]));
    let buf = cfs0002::tests::archive(&[page], &stored(&fsindex));
    let limits = Limits {
        max_file_len: 1 << 20,
        ..Limits::default()
    };
    let archive = Archive::open(
        buf,
        &OpenOptions {
            limits,
            ..OpenOptions::default()
        },
    )
    .unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::FileTooLarge { size: 2_000_000, .. }) = archive.read(idx));
}

/// Blocks cycling through pages force a decode each; the read stops instead of thrashing.
#[test]
fn blocks_cycling_through_pages_stop_the_read() {
    let blocks: Vec<_> = (0..30).map(|i| (i % 3, 0, 1)).collect();
    let fsindex = Fsindex::new(1).file("f", &blocks).finish();
    let page = |b| (stored(&[b; 1000]), cfs0002::tests::crc_slot(&[b; 1000]));
    let buf = cfs0002::tests::archive(&[page(1), page(2), page(3)], &stored(&fsindex));
    let limits = Limits {
        max_page_len: 1000,
        ..Limits::default()
    };
    let archive = Archive::open(
        buf,
        &OpenOptions {
            limits,
            ..OpenOptions::default()
        },
    )
    .unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::Overdecoded { size: 30, decoded: 3000 }) = archive.read(idx));
}

#[test]
fn a_file_revisiting_a_page_in_order_reads() {
    let fsindex = Fsindex::new(1)
        .file("f", &[(0, 0, 2), (1, 0, 2), (0, 2, 2)])
        .finish();
    let pages = [
        (stored(b"abcd"), cfs0002::tests::crc_slot(b"abcd")),
        (stored(b"wxyz"), cfs0002::tests::crc_slot(b"wxyz")),
    ];
    let archive = open(cfs0002::tests::archive(&pages, &stored(&fsindex))).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(archive.read(idx).unwrap() == b"abwxcd");
}

/// `KEY_INDEX` encrypts the pgindex, so the mode is checked before decoding it.
#[test]
fn a_key_index_archive_is_refused_as_encrypted_not_as_corrupt() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, 1)]).finish();
    let mut buf = cfs0003::tests::archive(&[vec![1]], &fsindex, 0x7B);
    let pgindex_codec = buf.len() - cfs0003::SIGNATURE.len() - 55 + 3;
    buf[pgindex_codec] = Compression::ZLIB.raw();
    check!(let Err(Error::Encrypted { mode: EncryptionMode::KEY_INDEX }) = open(buf));
}

/// A page the pgindex flags as encrypted is never handed back as plaintext.
#[test]
fn a_page_flagged_encrypted_is_refused() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, 3)]).finish();
    let mut buf = cfs0003::tests::archive(&[b"abc".to_vec()], &fsindex, 0x78);
    buf[3 + 4 + 2] = 1;
    let archive = open(buf).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::EncryptedPage { page: 0 }) = archive.read(idx));
}

/// A stored page whose bytes changed after its `crc32` slot was written.
#[test]
fn a_page_failing_its_hash_is_refused_unless_verification_is_off() {
    let fsindex = Fsindex::new(1).file("f", &[(0, 0, 5)]).finish();
    let page = (stored(b"hellp"), cfs0002::tests::crc_slot(b"hello"));
    let buf = cfs0002::tests::archive(&[page], &stored(&fsindex));

    let archive = open(buf.clone()).unwrap();
    let (_, idx) = archive.walk().next().unwrap();
    check!(let Err(Error::Decode { blob: Blob::Page(0), source: DecodeError::HashMismatch { hash: "CRC-32" } }) = archive.read(idx));

    let lax = OpenOptions {
        verify: false,
        ..OpenOptions::default()
    };
    let archive = Archive::open(buf, &lax).unwrap();
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
    let read_all = |buf: Vec<u8>| -> Result<()> {
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
fn two_filesets() -> Archive<Vec<u8>> {
    let fsindex = Fsindex::new(2)
        .dir("zeta", 1)
        .file("z.txt", &[(0, 0, 1)])
        .dir("alpha", 1)
        .file("a.txt", &[(0, 1, 1)])
        .finish_with(&[b"cookfs.fileset\0custom"]);
    let buf = cfs0003::tests::archive(&[b"za".to_vec()], &fsindex, 0x78);
    open(buf).unwrap()
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
    let archive = open(cfs0003::tests::archive(&[], &fsindex, 0x78)).unwrap();
    check!(archive.filesets().is_empty());
    check!(archive.fileset().is_none());
}

fn fixture(name: &str) -> Archive<Vec<u8>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    open(std::fs::read(path).unwrap()).unwrap()
}

/// Streaming must agree with a whole read, in one go or in pieces that straddle blocks and pages.
#[rstest::rstest]
#[case::cfs0002("v2-zlib-md5.cfs")]
#[case::cfs0003("v3-zstd.cfs")]
fn a_stream_reads_what_read_returns(#[case] name: &str) {
    use std::io::Read;
    let archive = fixture(name);
    for (path, id) in archive.page_order() {
        let whole = archive.read(id).unwrap();
        let mut streamed = Vec::new();
        archive
            .open_file(id)
            .unwrap()
            .read_to_end(&mut streamed)
            .unwrap();
        check!(streamed == whole, "{path}");

        let mut reader = archive.open_file(id).unwrap();
        let mut pieces = Vec::new();
        let mut buf = [0u8; 999];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            pieces.extend_from_slice(&buf[..n]);
        }
        check!(pieces == whole, "{path}");
    }
}

#[test]
fn a_stream_seeks_anywhere_in_its_file() {
    use std::io::{Read, Seek, SeekFrom};
    let archive = fixture("v3-zlib.cfs");
    let id = archive.lookup("data/random.bin").unwrap();
    let whole = archive.read(id).unwrap();
    let mut reader = archive.open_file(id).unwrap();
    check!(reader.len() == whole.len() as u64);

    for at in [0, 1, 4095, 4096, 4097, 12_345, whole.len() - 1] {
        reader.seek(SeekFrom::Start(at as u64)).unwrap();
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        check!(tail == whole[at..], "from {at}");
    }
    check!(reader.seek(SeekFrom::End(-3)).unwrap() == whole.len() as u64 - 3);
    check!(reader.seek(SeekFrom::Current(10)).unwrap() == whole.len() as u64 + 7);
    check!(reader.read(&mut [0; 8]).unwrap() == 0);
    check!(
        reader
            .seek(SeekFrom::Current(-(whole.len() as i64) - 8))
            .is_err()
    );
}

#[test]
fn lookup_follows_names_and_finds_nothing_for_a_missing_one() {
    let archive = fixture("v3-zlib.cfs");
    check!(archive.lookup("") == Some(archive.root()));
    let deep = archive.lookup("nested/a/b/c/deep.txt").unwrap();
    check!(archive.read(deep).unwrap() == b"deep\n");
    check!(archive.node(archive.lookup("nested/a").unwrap()).is_dir());
    for missing in ["nested/z", "nested//a", "readme.txt/x", "/readme.txt"] {
        check!(archive.lookup(missing).is_none(), "{missing}");
    }
}

#[test]
fn page_order_follows_the_data_not_the_names() {
    let archive = fixture("v3-zlib.cfs");
    let starts: Vec<_> = archive
        .page_order()
        .into_iter()
        .filter_map(|(_, id)| match &archive.node(id).kind {
            Kind::File(blocks) => blocks.first().map(|b| (b.page, b.offset)),
            _ => None,
        })
        .collect();
    check!(starts.windows(2).all(|w| w[0] <= w[1]));
    check!(
        archive.page_order().len()
            == archive
                .walk()
                .filter(|&(_, id)| !archive.node(id).is_dir())
                .count()
    );
}

#[test]
fn reading_a_directory_is_an_error() {
    let archive = fixture("v3-zlib.cfs");
    let dir = archive.lookup("data").unwrap();
    check!(let Err(Error::NotAFile) = archive.read(dir));
    check!(let Err(Error::NotAFile) = archive.open_file(dir));
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
    let archive = open(cfs0003::tests::archive(&[], &fsindex, 0x78)).unwrap();
    let portable: Vec<String> = archive
        .walk()
        .filter(|&(_, id)| archive.node(id).has_portable_name())
        .map(|(path, _)| path)
        .collect();
    check!(portable == ["ok.txt"]);

    let fsindex = Fsindex::new(1).dir("..", 1).file("inner", &[]).finish();
    let archive = open(cfs0003::tests::archive(&[], &fsindex, 0x78)).unwrap();
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
    let opts = OpenOptions {
        limits: Limits {
            max_fsindex_len: 4,
            ..Limits::default()
        },
        ..OpenOptions::default()
    };
    let check = Archive::open(one_file_v2(b"x"), &opts);
    check!(let Err(Error::Decode { blob: Blob::Fsindex, source: DecodeError::TooLarge { limit: 4, .. } }) = check);
}
