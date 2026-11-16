//! Builders every unit test shares: fsindex blobs, `CFS0002` and `CFS0003` archives, and open helpers.
//!
//! Each builder writes through [`Buf`], which can record the place and width of
//! every field it writes, so a sweep can set any one of them to a boundary
//! value. A plain [`Buf`] records nothing and costs nothing extra.

use std::collections::BTreeMap;
use std::fmt::Arguments;
use std::time::Duration;

use crate::index::MAGIC;
use crate::parsers::{cfs0002, cfs0003};
use crate::{Archive, Limits, OpenOptions, Result};

pub(crate) const MIB: usize = 1 << 20;

/// The longest a bounded operation may take before a test calls it unbounded.
pub(crate) const TIME_BOUND: Duration = Duration::from_secs(2);

/// Both formats end their trailer in a signature of this many bytes.
const SIGNATURE_LEN: usize = 7;
const _: () =
    assert!(cfs0002::SIGNATURE.len() == SIGNATURE_LEN && cfs0003::SIGNATURE.len() == SIGNATURE_LEN);

/// Where the signature starts in an archive that ends with one.
pub(crate) fn sig_at(buf: &[u8]) -> u64 {
    (buf.len() - SIGNATURE_LEN) as u64
}

/// The width and byte order of one recorded field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Width {
    U8,
    Be32,
    Be64,
    Le32,
    Le64,
}

impl Width {
    const fn len(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::Be32 | Self::Le32 => 4,
            Self::Be64 | Self::Le64 => 8,
        }
    }
}

/// One field written through [`Buf::put`].
#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) at: usize,
    pub(crate) width: Width,
}

impl Field {
    pub(crate) fn read(&self, buf: &[u8]) -> u64 {
        let b = &buf[self.at..];
        match self.width {
            Width::U8 => u64::from(b[0]),
            Width::Be32 => u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            Width::Le32 => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            Width::Be64 => u64::from_be_bytes(b[..8].try_into().unwrap()),
            Width::Le64 => u64::from_le_bytes(b[..8].try_into().unwrap()),
        }
    }

    pub(crate) fn write(&self, buf: &mut [u8], value: u64) {
        let b = &mut buf[self.at..];
        match self.width {
            Width::U8 => b[0] = value as u8,
            Width::Be32 => b[..4].copy_from_slice(&(value as u32).to_be_bytes()),
            Width::Le32 => b[..4].copy_from_slice(&(value as u32).to_le_bytes()),
            Width::Be64 => b[..8].copy_from_slice(&value.to_be_bytes()),
            Width::Le64 => b[..8].copy_from_slice(&value.to_le_bytes()),
        }
    }
}

/// Bytes being assembled, optionally with the place and width of every field written through [`Buf::put`].
#[derive(Default)]
pub(crate) struct Buf {
    pub(crate) bytes: Vec<u8>,
    pub(crate) fields: Vec<Field>,
    record: bool,
}

impl Buf {
    /// An empty buffer that records its fields when `record` is set.
    pub(crate) fn new(record: bool) -> Self {
        Self {
            record,
            ..Self::default()
        }
    }

    /// A buffer holding `bytes` and no fields.
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            ..Self::default()
        }
    }

    /// Appends a field, recording it under `name` when this buffer records.
    pub(crate) fn put(&mut self, name: Arguments<'_>, width: Width, value: u64) {
        let field = Field {
            name: if self.record {
                name.to_string()
            } else {
                String::new()
            },
            at: self.bytes.len(),
            width,
        };
        self.bytes.resize(self.bytes.len() + width.len(), 0);
        field.write(&mut self.bytes, value);
        if self.record {
            self.fields.push(field);
        }
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Appends `inner`, keeping the fields it recorded at their new places.
    pub(crate) fn nest(&mut self, inner: Self) {
        let base = self.bytes.len();
        self.fields.extend(inner.fields.into_iter().map(|f| Field {
            at: f.at + base,
            ..f
        }));
        self.bytes.extend_from_slice(&inner.bytes);
    }

    /// A `CFS0002` hash slot; a `crc32`-mode slot records its size field.
    fn slot(&mut self, page: usize, slot: [u8; 16]) {
        let crc_mode = slot[..8] == [0; 8] && slot != [0; 16];
        if crc_mode {
            self.raw(&[0; 8]);
            let size = u32::from_be_bytes([slot[8], slot[9], slot[10], slot[11]]);
            self.put(
                format_args!("page {page} slot size"),
                Width::Be32,
                size.into(),
            );
            self.raw(&slot[12..]);
        } else {
            self.raw(&slot);
        }
    }
}

/// One fsindex entry, for building a tree whose child counts follow from its shape.
pub(crate) enum Entry {
    Dir(&'static str, Vec<Self>),
    File(&'static str, Vec<(i32, i32, i32)>),
}

/// Builds fsindex blobs entry by entry, in the order they appear on disk.
///
/// The counts a caller passes are written as given, so a test can lie about
/// them; [`Fsindex::tree`] derives them instead.
pub(crate) struct Fsindex {
    buf: Buf,
}

impl Fsindex {
    pub(crate) fn new(root_children: u32) -> Self {
        Self::start(Buf::default(), root_children)
    }

    /// A builder whose [`Fsindex::finish_buf`] knows where every field landed.
    pub(crate) fn recording(root_children: u32) -> Self {
        Self::start(Buf::new(true), root_children)
    }

    fn start(mut buf: Buf, root_children: u32) -> Self {
        buf.raw(MAGIC);
        buf.put(
            format_args!("root child count"),
            Width::Be32,
            root_children.into(),
        );
        Self { buf }
    }

    /// An entry's name and mtime, then its block count.
    fn head(&mut self, name: &str, block_count: i32) {
        let b = &mut self.buf;
        b.put(
            format_args!("{name} name length"),
            Width::U8,
            name.len() as u64,
        );
        b.raw(name.as_bytes());
        b.raw(&[0]);
        b.put(format_args!("{name} mtime"), Width::Be64, 1_700_000_000);
        b.put(
            format_args!("{name} block count"),
            Width::Be32,
            block_count.cast_unsigned().into(),
        );
    }

    pub(crate) fn file(mut self, name: &str, blocks: &[(i32, i32, i32)]) -> Self {
        self.head(name, blocks.len() as i32);
        for (i, &(page, offset, size)) in blocks.iter().enumerate() {
            for (field, value) in [("page", page), ("offset", offset), ("size", size)] {
                self.buf.put(
                    format_args!("{name} block {i} {field}"),
                    Width::Be32,
                    value.cast_unsigned().into(),
                );
            }
        }
        self
    }

    pub(crate) fn dir(mut self, name: &str, children: u32) -> Self {
        self.head(name, -1);
        self.buf.put(
            format_args!("{name} child count"),
            Width::Be32,
            children.into(),
        );
        self
    }

    /// Appends `entries`, each directory followed by its own children.
    pub(crate) fn tree(self, entries: &[Entry]) -> Self {
        entries.iter().fold(self, |fs, entry| match entry {
            Entry::Dir(name, children) => fs.dir(name, children.len() as u32).tree(children),
            Entry::File(name, blocks) => fs.file(name, blocks),
        })
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.finish_with(&[])
    }

    /// Ends the tree with these raw metadata records.
    pub(crate) fn finish_with(self, records: &[&[u8]]) -> Vec<u8> {
        self.finish_buf(records).bytes
    }

    /// Like [`Fsindex::finish_with`], keeping the recorded fields.
    pub(crate) fn finish_buf(mut self, records: &[&[u8]]) -> Buf {
        let b = &mut self.buf;
        b.put(
            format_args!("metadata count"),
            Width::Be32,
            records.len() as u64,
        );
        for (i, record) in records.iter().enumerate() {
            b.put(
                format_args!("metadata {i} length"),
                Width::Be32,
                record.len() as u64,
            );
            b.raw(record);
        }
        self.buf
    }
}

/// A stored `CFS0002` blob: id byte 0, then the payload.
pub(crate) fn stored(payload: &[u8]) -> Vec<u8> {
    let mut blob = vec![0u8];
    blob.extend_from_slice(payload);
    blob
}

/// The `crc32`-mode slot upstream writes for a page that decodes to `decoded`.
pub(crate) fn crc_slot(decoded: &[u8]) -> [u8; 16] {
    let mut slot = [0u8; 16];
    slot[8..12].copy_from_slice(&(decoded.len() as u32).to_be_bytes());
    slot[12..].copy_from_slice(&crc32fast::hash(decoded).to_be_bytes());
    slot
}

/// The `md5`-mode slot upstream writes for a page that decodes to `decoded`.
pub(crate) fn md5_slot(decoded: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(decoded).into()
}

/// A stored `CFS0002` page of `payload` with its `crc32` slot.
pub(crate) fn stored_page(payload: &[u8]) -> (Vec<u8>, [u8; 16]) {
    (stored(payload), crc_slot(payload))
}

/// Ten bytes whose every offset reads back as its own value.
pub(crate) const DIGITS: &[u8] = b"0123456789";

/// A `CFS0002` archive whose one stored page holds [`DIGITS`], under this decoded fsindex.
pub(crate) fn digits_v2(fsindex: &[u8]) -> Vec<u8> {
    archive_v2(&[stored_page(DIGITS)], &stored(fsindex))
}

/// A `CFS0002` archive from already-encoded page blobs with their hash slots, and a fsindex blob.
pub(crate) fn archive_v2(pages: &[(Vec<u8>, [u8; 16])], fsindex: &[u8]) -> Vec<u8> {
    let pages = pages
        .iter()
        .map(|(blob, slot)| (Buf::of(blob), *slot))
        .collect();
    assemble_v2(pages, Buf::of(fsindex)).bytes
}

/// Lays out a `CFS0002` archive; it records its fields when `index` does.
pub(crate) fn assemble_v2(pages: Vec<(Buf, [u8; 16])>, index: Buf) -> Buf {
    let lens: Vec<usize> = pages.iter().map(|(body, _)| body.bytes.len()).collect();
    let mut out = Buf::new(index.record);
    let mut slots = Vec::new();
    for (body, slot) in pages {
        out.nest(body);
        slots.push(slot);
    }
    for (i, slot) in slots.into_iter().enumerate() {
        out.slot(i, slot);
    }
    for (i, len) in lens.iter().enumerate() {
        out.put(
            format_args!("page {i} stored length"),
            Width::Be32,
            *len as u64,
        );
    }
    let index_len = index.bytes.len();
    out.nest(index);
    out.put(
        format_args!("fsindex length"),
        Width::Be32,
        index_len as u64,
    );
    out.put(format_args!("page count"), Width::Be32, lens.len() as u64);
    out.put(format_args!("default compression"), Width::U8, 0);
    out.raw(cfs0002::SIGNATURE);
    out
}

/// One file, `hello.txt`, holding `payload` in page 0.
pub(crate) fn one_file_v2(payload: &[u8]) -> Vec<u8> {
    let fsindex = Fsindex::new(1)
        .file("hello.txt", &[(0, 0, payload.len() as i32)])
        .finish();
    archive_v2(&[stored_page(payload)], &stored(&fsindex))
}

/// One file, `hello.txt`, holding `payload` in page 0, under an unencrypted level-15 suffix.
pub(crate) fn one_file_v3(payload: &[u8]) -> Vec<u8> {
    let fsindex = Fsindex::new(1)
        .file("hello.txt", &[(0, 0, payload.len() as i32)])
        .finish();
    archive_v3(&[payload.to_vec()], &fsindex, 0x78)
}

/// One `CFS0003` page: its codec id, its body, and the length that body decodes to.
pub(crate) struct Page3 {
    pub(crate) codec: u8,
    pub(crate) body: Buf,
    pub(crate) plain: usize,
}

/// A stored pgindex blob describing `pages` as `(compressed, uncompressed)` sizes.
pub(crate) fn pgindex(pages: &[(u32, u32)]) -> Vec<u8> {
    let rows: Vec<_> = pages.iter().map(|&(c, u)| (0, c, u)).collect();
    pgindex_buf(false, &rows).bytes
}

/// A pgindex of `(codec, compressed, uncompressed)` rows, each field recorded when `record` is set.
fn pgindex_buf(record: bool, rows: &[(u8, u32, u32)]) -> Buf {
    let n = rows.len();
    let mut b = Buf::new(record);
    b.put(format_args!("pgindex count"), Width::Be32, n as u64);
    for (i, &(codec, ..)) in rows.iter().enumerate() {
        b.put(format_args!("page {i} codec"), Width::U8, codec.into());
    }
    b.raw(&vec![0; 2 * n]); // levels, then encrypted flags
    for (i, &(_, stored, _)) in rows.iter().enumerate() {
        b.put(
            format_args!("page {i} stored length"),
            Width::Be32,
            stored.into(),
        );
    }
    for (i, &(.., plain)) in rows.iter().enumerate() {
        b.put(
            format_args!("page {i} decoded length"),
            Width::Be32,
            plain.into(),
        );
    }
    b.raw(&vec![0; 16 * n]);
    b
}

/// A `CFS0003` archive with stored pages and a stored fsindex, under this encryption byte.
pub(crate) fn archive_v3(pages: &[Vec<u8>], fsindex: &[u8], encryption: u8) -> Vec<u8> {
    let pages = pages
        .iter()
        .map(|p| Page3 {
            codec: 0,
            body: Buf::of(p),
            plain: p.len(),
        })
        .collect();
    assemble_v3(pages, Buf::of(fsindex), encryption).bytes
}

/// Lays out a `CFS0003` archive with a stored pgindex and fsindex; it records its fields when `index` does.
pub(crate) fn assemble_v3(pages: Vec<Page3>, index: Buf, encryption: u8) -> Buf {
    let rows: Vec<_> = pages
        .iter()
        .map(|p| (p.codec, p.body.bytes.len() as u32, p.plain as u32))
        .collect();
    let pgindex = pgindex_buf(index.record, &rows);
    let mut out = Buf::new(index.record);
    for p in pages {
        out.nest(p.body);
    }
    let lens = [
        ("pgindex", pgindex.bytes.len()),
        ("fsindex", index.bytes.len()),
    ];
    out.nest(pgindex);
    out.nest(index);
    out.put(format_args!("base compression"), Width::U8, 0);
    out.put(format_args!("base level"), Width::U8, 0);
    out.put(format_args!("encryption"), Width::U8, encryption.into());
    for (blob, len) in lens {
        out.put(format_args!("{blob} codec"), Width::U8, 0);
        out.put(format_args!("{blob} level"), Width::U8, 0);
        out.raw(&[0; 16]);
        out.put(
            format_args!("{blob} stored length"),
            Width::Be32,
            len as u64,
        );
        out.put(
            format_args!("{blob} decoded length"),
            Width::Be32,
            len as u64,
        );
    }
    out.raw(cfs0003::SIGNATURE);
    out
}

fn options(edit: impl FnOnce(&mut OpenOptions)) -> OpenOptions {
    let mut opts = OpenOptions::default();
    edit(&mut opts);
    opts
}

pub(crate) fn open(buf: Vec<u8>) -> Result<Archive<Vec<u8>>> {
    Archive::open(buf, &OpenOptions::default())
}

/// Opens `buf` under `limits`, verifying hashes.
pub(crate) fn open_with(buf: Vec<u8>, limits: Limits) -> Result<Archive<Vec<u8>>> {
    Archive::open(buf, &options(|o| o.limits = limits))
}

/// Opens `buf` without checking page or index hashes.
pub(crate) fn open_unverified(buf: Vec<u8>) -> Result<Archive<Vec<u8>>> {
    Archive::open(buf, &options(|o| o.verify = false))
}

/// Every path of the archive in `buf`, directories included, with its contents or `None` for a directory.
pub(crate) fn read_all(buf: Vec<u8>, limits: Limits) -> Result<BTreeMap<String, Option<Vec<u8>>>> {
    let archive = open_with(buf, limits)?;
    archive
        .walk()
        .map(|(path, idx)| {
            let data = (!archive.node(idx).is_dir())
                .then(|| archive.read(idx))
                .transpose()?;
            Ok((path, data))
        })
        .collect()
}
