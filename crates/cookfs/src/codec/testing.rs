//! Reference encoders the codec tests and the hostile-archive tests build streams with.

use std::io::Read;
#[cfg(feature = "codec-brotli")]
use std::io::Write;

pub(crate) const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog";

pub(super) fn exact(len: usize) -> super::Expect {
    super::Expect {
        declared: Some(len),
        limit: usize::MAX,
    }
}

pub(crate) fn deflate(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::DeflateEncoder::new(payload, flate2::Compression::default())
        .read_to_end(&mut out)
        .unwrap();
    out
}

pub(crate) fn lzma_alone_stream(payload: &[u8]) -> Vec<u8> {
    let options = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
    let stream = liblzma::stream::Stream::new_lzma_encoder(&options).unwrap();
    let mut out = Vec::new();
    liblzma::read::XzEncoder::new_stream(payload, stream)
        .read_to_end(&mut out)
        .unwrap();
    out
}

/// The 5-byte-header raw LZMA1 shape `CFS0003` writes for id 3.
pub(crate) fn raw_lzma1_stream(payload: &[u8]) -> Vec<u8> {
    let mut opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
    let dict_size = 1u32 << 16;
    opts.dict_size(dict_size);
    let mut filters = liblzma::stream::Filters::new();
    filters.lzma1(&opts);
    let stream = liblzma::stream::Stream::new_raw_encoder(&filters).unwrap();
    let mut compressed = Vec::new();
    liblzma::read::XzEncoder::new_stream(payload, stream)
        .read_to_end(&mut compressed)
        .unwrap();
    let mut out = vec![0x5Du8]; // lc=3, lp=0, pb=2: the preset's defaults
    out.extend_from_slice(&dict_size.to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

#[cfg(feature = "codec-bzip2")]
pub(crate) fn bzip2_stream(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    bzip2::read::BzEncoder::new(payload, bzip2::Compression::default())
        .read_to_end(&mut out)
        .unwrap();
    out
}

#[cfg(feature = "codec-zstd")]
/// A one-shot frame, as upstream's `ZSTD_compress` writes: single-segment, so its window is its size.
pub(crate) fn zstd_stream(payload: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(payload, 0).unwrap()
}

#[cfg(feature = "codec-brotli")]
pub(crate) fn brotli_stream(payload: &[u8]) -> Vec<u8> {
    let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 9, 22);
    encoder.write_all(payload).unwrap();
    encoder.into_inner()
}
