//! Assembles an archive from an arbitrary description, in both formats, and checks every read.
//!
//! A well-formed description (every block inside its page, every claimed count
//! honest, every name unique and addressable, no field overridden) has exactly
//! one right reading, and both formats must produce it. Any other description
//! must still open or fail without a panic, and a file that reads must read to
//! the size its blocks sum to.

#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use cookfs::{Archive, Limits, OpenOptions};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 1 << 20;
const MAX_DEPTH: usize = 32;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Codec {
    Stored,
    Zlib,
    Bzip2,
    Lzma,
    Zstd,
    Brotli,
}

#[derive(Arbitrary, Debug)]
struct PageDesc {
    codec: Codec,
    data: Vec<u8>,
    /// Replaces the decoded size the trailer records.
    declared: Option<u32>,
    /// Replaces the stored length the trailer records.
    stored: Option<u32>,
    /// Bytes put in place of the encoded body.
    garbage: Option<Vec<u8>>,
}

#[derive(Arbitrary, Debug)]
struct BlockDesc {
    page: u8,
    offset: u16,
    len: u16,
    /// Written as is instead of the block derived from the fields above.
    raw: Option<(i32, i32, i32)>,
}

#[derive(Arbitrary, Debug)]
enum Node {
    Dir {
        name: Vec<u8>,
        mtime: i64,
        children: Vec<Node>,
        /// Replaces the child count written.
        claim: Option<u32>,
    },
    File {
        name: Vec<u8>,
        mtime: i64,
        blocks: Vec<BlockDesc>,
    },
}

#[derive(Arbitrary, Debug)]
struct Desc {
    pages: Vec<PageDesc>,
    root: Vec<Node>,
    metadata: Vec<Vec<u8>>,
    crc_slots: bool,
    fsindex_zlib: bool,
    encryption: u8,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

type Contents = BTreeMap<String, Option<Vec<u8>>>;

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    bzip2::read::BzEncoder::new(data, bzip2::Compression::fast())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn lzma_alone(data: &[u8]) -> Vec<u8> {
    let mut opts = liblzma::stream::LzmaOptions::new_preset(0).unwrap();
    opts.dict_size(1 << 16);
    let stream = liblzma::stream::Stream::new_lzma_encoder(&opts).unwrap();
    let mut out = Vec::new();
    liblzma::read::XzEncoder::new_stream(data, stream)
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// The 5-byte-header raw LZMA1 that `CFS0003` writes for id 3.
fn raw_lzma1(data: &[u8]) -> Vec<u8> {
    const DICT: u32 = 1 << 16;
    let mut opts = liblzma::stream::LzmaOptions::new_preset(0).unwrap();
    opts.dict_size(DICT);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma1(&opts);
    let stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
    let mut out = vec![0x5D]; // lc=3, lp=0, pb=2, as the preset sets them
    out.extend_from_slice(&DICT.to_le_bytes());
    liblzma::read::XzEncoder::new_stream(data, stream)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut enc = brotli::CompressorWriter::new(Vec::new(), 4096, 1, 16);
    enc.write_all(data).unwrap();
    enc.into_inner()
}

/// A page's codec id and body as `v3` or `CFS0002` stores it.
fn encode(codec: Codec, data: &[u8], v3: bool) -> (u8, Vec<u8>) {
    match codec {
        Codec::Stored => (0, data.to_vec()),
        Codec::Zlib => (1, deflate(data)),
        Codec::Bzip2 if v3 => (2, bzip2(data)),
        Codec::Bzip2 => {
            let mut body = (data.len() as u32).to_be_bytes().to_vec();
            body.extend_from_slice(&bzip2(data));
            (2, body)
        }
        Codec::Lzma if v3 => (3, raw_lzma1(data)),
        Codec::Lzma => (255, lzma_alone(data)),
        Codec::Zstd => (4, zstd::bulk::compress(data, 1).unwrap()),
        Codec::Brotli => (5, brotli(data)),
    }
}

/// Writes the fsindex entries for `nodes`, recording what a correct reader must see when the tree is well formed.
struct Tree<'a> {
    pages: &'a [PageDesc],
    out: Vec<u8>,
    contents: Contents,
    well_formed: bool,
}

impl Tree<'_> {
    fn entries(&mut self, nodes: &[Node], prefix: &str, depth: usize) {
        let mut seen = BTreeSet::new();
        for node in nodes {
            let (name, mtime) = match node {
                Node::Dir { name, mtime, .. } | Node::File { name, mtime, .. } => (name, *mtime),
            };
            let name = &name[..name.len().min(255)];
            let path = match std::str::from_utf8(name) {
                Ok(s) if !s.is_empty() && !s.contains('/') && seen.insert(s.to_owned()) => {
                    if prefix.is_empty() {
                        s.to_owned()
                    } else {
                        format!("{prefix}/{s}")
                    }
                }
                _ => {
                    self.well_formed = false;
                    String::new()
                }
            };
            self.out.push(name.len() as u8);
            self.out.extend_from_slice(name);
            self.out.push(0);
            self.out.extend_from_slice(&mtime.to_be_bytes());
            match node {
                Node::Dir {
                    children, claim, ..
                } => {
                    self.out.extend_from_slice(&(-1i32).to_be_bytes());
                    let count = claim.unwrap_or(children.len() as u32);
                    if count as usize != children.len() || depth >= MAX_DEPTH {
                        self.well_formed = false;
                    }
                    self.out.extend_from_slice(&count.to_be_bytes());
                    self.contents.insert(path.clone(), None);
                    self.entries(children, &path, depth + 1);
                }
                Node::File { blocks, .. } => {
                    self.out
                        .extend_from_slice(&(blocks.len() as i32).to_be_bytes());
                    let mut data = Vec::new();
                    for block in blocks {
                        let (page, offset, size) = self.block(block, &mut data);
                        for v in [page, offset, size] {
                            self.out.extend_from_slice(&v.to_be_bytes());
                        }
                    }
                    self.contents.insert(path, Some(data));
                }
            }
        }
    }

    fn block(&mut self, block: &BlockDesc, data: &mut Vec<u8>) -> (i32, i32, i32) {
        if let Some(raw) = block.raw {
            self.well_formed = false;
            return raw;
        }
        if self.pages.is_empty() {
            return (-1, 0, 0);
        }
        let page = usize::from(block.page) % self.pages.len();
        let bytes = &self.pages[page].data;
        let offset = usize::from(block.offset) % (bytes.len() + 1);
        let len = usize::from(block.len).min(bytes.len() - offset);
        data.extend_from_slice(&bytes[offset..offset + len]);
        (page as i32, offset as i32, len as i32)
    }
}

fn fsindex(desc: &Desc) -> (Vec<u8>, Option<Contents>) {
    let mut tree = Tree {
        pages: &desc.pages,
        out: b"CFS2.200".to_vec(),
        contents: BTreeMap::new(),
        well_formed: true,
    };
    tree.out
        .extend_from_slice(&(desc.root.len() as u32).to_be_bytes());
    tree.entries(&desc.root, "", 1);
    tree.out
        .extend_from_slice(&(desc.metadata.len() as u32).to_be_bytes());
    for record in &desc.metadata {
        tree.out
            .extend_from_slice(&(record.len() as u32).to_be_bytes());
        tree.out.extend_from_slice(record);
    }
    let overridden = desc
        .pages
        .iter()
        .any(|p| p.declared.is_some() || p.stored.is_some() || p.garbage.is_some());
    let decoys = desc.suffix.windows(6).any(|w| w == b"CFS000");
    let well_formed = tree.well_formed && !overridden && !decoys;
    (tree.out, well_formed.then_some(tree.contents))
}

fn v2(desc: &Desc, index: &[u8]) -> Vec<u8> {
    let mut buf = desc.prefix.clone();
    let mut slots = Vec::new();
    let mut sizes = Vec::new();
    for page in &desc.pages {
        let (id, body) = encode(page.codec, &page.data, false);
        let mut blob = vec![id];
        blob.extend_from_slice(page.garbage.as_deref().unwrap_or(&body));
        let declared = page.declared.unwrap_or(page.data.len() as u32);
        if desc.crc_slots {
            slots.extend_from_slice(&[0; 8]);
            slots.extend_from_slice(&declared.to_be_bytes());
            slots.extend_from_slice(&[0; 4]);
        } else {
            slots.extend_from_slice(&[0xA5; 16]);
        }
        sizes.extend_from_slice(&page.stored.unwrap_or(blob.len() as u32).to_be_bytes());
        buf.extend_from_slice(&blob);
    }
    buf.extend_from_slice(&slots);
    buf.extend_from_slice(&sizes);
    let mut blob = vec![u8::from(desc.fsindex_zlib)];
    blob.extend_from_slice(&if desc.fsindex_zlib {
        deflate(index)
    } else {
        index.to_vec()
    });
    buf.extend_from_slice(&blob);
    buf.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    buf.extend_from_slice(&(desc.pages.len() as u32).to_be_bytes());
    buf.push(0);
    buf.extend_from_slice(b"CFS0002");
    buf.extend_from_slice(&desc.suffix);
    buf
}

fn v3(desc: &Desc, index: &[u8]) -> Vec<u8> {
    let mut buf = desc.prefix.clone();
    let n = desc.pages.len();
    let mut ids = Vec::new();
    let mut stored = Vec::new();
    let mut declared = Vec::new();
    for page in &desc.pages {
        let (id, body) = encode(page.codec, &page.data, true);
        let body = page.garbage.as_deref().unwrap_or(&body);
        ids.push(id);
        stored.extend_from_slice(&page.stored.unwrap_or(body.len() as u32).to_be_bytes());
        declared.extend_from_slice(
            &page
                .declared
                .unwrap_or(page.data.len() as u32)
                .to_be_bytes(),
        );
        buf.extend_from_slice(body);
    }
    let mut pgindex = (n as u32).to_be_bytes().to_vec();
    pgindex.extend_from_slice(&ids);
    pgindex.extend(std::iter::repeat_n(0u8, 2 * n));
    pgindex.extend_from_slice(&stored);
    pgindex.extend_from_slice(&declared);
    pgindex.extend(std::iter::repeat_n(0u8, 16 * n));
    let fs = if desc.fsindex_zlib {
        deflate(index)
    } else {
        index.to_vec()
    };
    buf.extend_from_slice(&pgindex);
    buf.extend_from_slice(&fs);
    buf.extend_from_slice(&[0, 0, desc.encryption]);
    for (codec, stored, plain) in [
        (0u8, pgindex.len(), pgindex.len()),
        (u8::from(desc.fsindex_zlib), fs.len(), index.len()),
    ] {
        buf.extend_from_slice(&[codec, 0]);
        buf.extend_from_slice(&[0; 16]);
        buf.extend_from_slice(&(stored as u32).to_be_bytes());
        buf.extend_from_slice(&(plain as u32).to_be_bytes());
    }
    buf.extend_from_slice(b"CFS0003");
    buf.extend_from_slice(&desc.suffix);
    buf
}

fn check(format: &str, buf: Vec<u8>, want: Option<&Contents>) {
    let mut limits = Limits::default();
    limits.max_fsindex_len = LIMIT;
    limits.max_page_len = LIMIT;
    limits.max_depth = MAX_DEPTH;
    let mut opts = OpenOptions::default();
    opts.limits = limits;
    let archive = match Archive::open(buf, &opts) {
        Ok(archive) => archive,
        Err(e) => {
            assert!(
                want.is_none(),
                "{format}: a well-formed archive failed to open: {e}"
            );
            return;
        }
    };
    let mut got = BTreeMap::new();
    for (path, idx) in archive.walk() {
        let node = archive.node(idx);
        let data = if node.is_dir() {
            None
        } else {
            match archive.read(idx) {
                Ok(data) => {
                    assert_eq!(
                        data.len() as u64,
                        node.size(),
                        "{format}: {path} read short of its blocks"
                    );
                    Some(data)
                }
                Err(e) => {
                    assert!(
                        want.is_none(),
                        "{format}: {path} of a well-formed archive failed: {e}"
                    );
                    continue;
                }
            }
        };
        got.insert(path, data);
    }
    if let Some(want) = want {
        assert_eq!(
            &got, want,
            "{format}: read back something other than was written"
        );
    }
}

fuzz_target!(|desc: Desc| {
    let (index, want) = fsindex(&desc);
    check("CFS0002", v2(&desc, &index), want.as_ref());
    let want = want.filter(|_| desc.encryption & 0b111 == 0);
    check("CFS0003", v3(&desc, &index), want.as_ref());
});
