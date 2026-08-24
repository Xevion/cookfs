//! Codec dispatch for page and fsindex blobs.
//!
//! Every blob a CFS0002 archive stores, whether a page or the fsindex itself,
//! opens with a 1-byte codec id naming how the rest of the blob is compressed.

use std::io::Read;

use snafu::{OptionExt, ResultExt};

use crate::read::{
    CodecUnavailableSnafu, DecompressSnafu, EmptyBlobSnafu, Result, UnknownCodecSnafu,
};

/// A compression codec named by a blob's leading id byte.
///
/// Every id a CFS0002 archive is known to emit is represented here, even ids
/// this build cannot decode: [`Codec::from_id`] should never fail on a real
/// archive, only `decode` should, and only for the codecs not yet wired up.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Uncompressed passthrough (id 0).
    Stored,
    /// zlib/deflate (id 1).
    Deflate,
    /// bzip2 (id 2). Requires the `codec-bzip2` feature, on by default.
    Bzip2,
    /// Raw LZMA1 (id 3): `CFS0003`'s own codec, distinct from BitRock's
    /// `.lzma`-alone container at id 255 despite sharing an algorithm.
    Lzma,
    /// Zstandard (id 4). Requires the `codec-zstd` feature, on by default.
    Zstd,
    /// Brotli (id 5). Requires the `codec-brotli` feature, on by default.
    Brotli,
    /// BitRock's legacy LZMA-alone codec, wired into the custom slot (id 255).
    LegacyCustom,
    /// The modern custom codec slot (id 254).
    ///
    /// Support would require a caller-supplied decoder; no such extension
    /// point is exposed yet, so this variant always decodes as unavailable.
    ModernCustom,
}

impl Codec {
    /// Maps a blob's wire codec id to its variant.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownCodec`] for any id outside the known set.
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::Stored),
            1 => Ok(Self::Deflate),
            2 => Ok(Self::Bzip2),
            3 => Ok(Self::Lzma),
            4 => Ok(Self::Zstd),
            5 => Ok(Self::Brotli),
            254 => Ok(Self::ModernCustom),
            255 => Ok(Self::LegacyCustom),
            id => UnknownCodecSnafu { id }.fail(),
        }
    }

    /// The wire id this variant was decoded from.
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            Self::Stored => 0,
            Self::Deflate => 1,
            Self::Bzip2 => 2,
            Self::Lzma => 3,
            Self::Zstd => 4,
            Self::Brotli => 5,
            Self::ModernCustom => 254,
            Self::LegacyCustom => 255,
        }
    }
}

/// Decodes one blob: a leading 1-byte codec id, then the compressed payload.
///
/// `uncompressed_len` is the blob's own declared decompressed size. Every
/// codec's read is bounded to this length so a decompression bomb from
/// untrusted input cannot exhaust memory, and [`Codec::Lzma`] additionally
/// relies on it as the termination signal a raw LZMA1 stream lacks.
///
/// # Errors
///
/// Returns [`crate::Error::EmptyBlob`] for a zero-length blob,
/// [`crate::Error::UnknownCodec`] for an id outside the known set,
/// [`crate::Error::CodecUnavailable`] for a known id this build cannot decode,
/// and [`crate::Error::Decompress`] if a codec's decoder rejects the payload.
pub fn decode(blob: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    let (&id, body) = blob.split_first().context(EmptyBlobSnafu)?;
    decode_with(Codec::from_id(id)?, body, uncompressed_len)
}

/// Decodes a payload whose codec is already known, with no leading id byte.
///
/// `CFS0003` names each page's codec out of band, in the pgindex table, so
/// its page and index blobs carry no leading id byte for [`decode`] to strip.
/// `uncompressed_len` is the blob's own declared decompressed size. Every
/// codec's read is bounded to this length so a decompression bomb from
/// untrusted input cannot exhaust memory, and [`Codec::Lzma`] additionally
/// relies on it as the termination signal a raw LZMA1 stream lacks.
///
/// # Errors
///
/// Returns [`crate::Error::CodecUnavailable`] for a known id this build
/// cannot decode, and [`crate::Error::Decompress`] if the codec's decoder
/// rejects the payload.
pub fn decode_with(codec: Codec, body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    match codec {
        Codec::Stored => Ok(body.to_vec()),
        Codec::Deflate => decode_deflate(body, uncompressed_len),
        Codec::Lzma => decode_raw_lzma1(body, uncompressed_len),
        Codec::LegacyCustom => decode_lzma_alone(body, uncompressed_len),
        #[cfg(feature = "codec-bzip2")]
        Codec::Bzip2 => decode_bzip2(body, uncompressed_len),
        #[cfg(not(feature = "codec-bzip2"))]
        codec @ Codec::Bzip2 => unavailable(codec, "bzip2"),
        #[cfg(feature = "codec-zstd")]
        Codec::Zstd => decode_zstd(body, uncompressed_len),
        #[cfg(not(feature = "codec-zstd"))]
        codec @ Codec::Zstd => unavailable(codec, "zstd"),
        #[cfg(feature = "codec-brotli")]
        Codec::Brotli => decode_brotli(body, uncompressed_len),
        #[cfg(not(feature = "codec-brotli"))]
        codec @ Codec::Brotli => unavailable(codec, "brotli"),
        codec @ Codec::ModernCustom => unavailable(codec, "modern-custom"),
    }
}

fn unavailable(codec: Codec, feature: &'static str) -> Result<Vec<u8>> {
    CodecUnavailableSnafu {
        id: codec.id(),
        feature,
    }
    .fail()
}

/// The read is bounded to `uncompressed_len` so a decompression bomb from
/// untrusted input cannot exhaust memory even when the codec reports its own
/// end-of-stream cleanly.
fn decode_deflate(body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(body)
        .take(uncompressed_len as u64)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "deflate" })?;
    Ok(out)
}

#[cfg(feature = "codec-bzip2")]
fn decode_bzip2(body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    bzip2::read::BzDecoder::new(body)
        .take(uncompressed_len as u64)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "bzip2" })?;
    Ok(out)
}

#[cfg(feature = "codec-zstd")]
fn decode_zstd(body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    zstd::stream::read::Decoder::new(body)
        .context(DecompressSnafu { codec: "zstd" })?
        .take(uncompressed_len as u64)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "zstd" })?;
    Ok(out)
}

#[cfg(feature = "codec-brotli")]
fn decode_brotli(body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    const BUFFER_SIZE: usize = 4096;
    let mut out = Vec::new();
    brotli::Decompressor::new(body, BUFFER_SIZE)
        .take(uncompressed_len as u64)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "brotli" })?;
    Ok(out)
}

/// BitRock's legacy custom slot (id 255): the classic `.lzma`-alone
/// container, a 13-byte header (properties, dictionary size, uncompressed
/// size) that `liblzma`'s alone decoder consumes itself.
fn decode_lzma_alone(body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)
        .map_err(std::io::Error::other)
        .context(DecompressSnafu { codec: "lzma" })?;
    liblzma::read::XzDecoder::new_stream(body, stream)
        .take(uncompressed_len as u64)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "lzma" })?;
    Ok(out)
}

/// `CFS0003`'s id-3 LZMA blobs (pages, pgindex, fsindex) are raw LZMA1
/// streams, not the classic `.lzma`-alone container: a 5-byte properties
/// header (1 properties byte, 4-byte little-endian dictionary size) with no
/// uncompressed-size field and no end-of-stream marker.
///
/// With no end marker, `liblzma`'s decoder never reports [`Status::StreamEnd`]
/// and its `Read` wrapper errors the moment input runs out, so the read is
/// bounded to `uncompressed_len`, the blob's own declared size, instead of
/// running to a completion signal that never comes.
///
/// [`Status::StreamEnd`]: liblzma::stream::Status::StreamEnd
fn decode_raw_lzma1(body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    const HEADER_LEN: usize = 5;
    let (header, payload) = body.split_at(HEADER_LEN.min(body.len()));

    let mut filters = liblzma::stream::Filters::new();
    filters
        .lzma1_properties(header)
        .map_err(std::io::Error::other)
        .context(DecompressSnafu { codec: "lzma" })?;

    let mut out = Vec::new();
    let stream = liblzma::stream::Stream::new_raw_decoder(&filters)
        .map_err(std::io::Error::other)
        .context(DecompressSnafu { codec: "lzma" })?;
    liblzma::read::XzDecoder::new_stream(payload, stream)
        .take(uncompressed_len as u64)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "lzma" })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    #[cfg(any(feature = "codec-zstd", feature = "codec-brotli"))]
    use std::io::Write;

    #[test]
    fn from_id_maps_every_known_id_to_its_variant() {
        let cases = [
            (0u8, Codec::Stored),
            (1, Codec::Deflate),
            (2, Codec::Bzip2),
            (3, Codec::Lzma),
            (4, Codec::Zstd),
            (5, Codec::Brotli),
            (254, Codec::ModernCustom),
            (255, Codec::LegacyCustom),
        ];
        for (id, expected) in cases {
            check!(Codec::from_id(id).unwrap() == expected);
            check!(expected.id() == id);
        }
    }

    #[test]
    fn from_id_rejects_unknown_ids() {
        for id in [6u8, 100, 200, 253] {
            let err = Codec::from_id(id).unwrap_err();
            check!(matches!(err, crate::Error::UnknownCodec { id: got } if got == id));
        }
    }

    #[test]
    fn decode_of_stored_is_identity() {
        let mut blob = vec![0u8];
        blob.extend_from_slice(b"payload bytes");
        check!(decode(&blob, 13).unwrap() == b"payload bytes");
    }

    #[test]
    fn decode_of_deflate_round_trips_a_known_stream() {
        let mut compressed = Vec::new();
        flate2::read::DeflateEncoder::new(
            &b"the quick brown fox jumps over the lazy dog"[..],
            flate2::Compression::default(),
        )
        .read_to_end(&mut compressed)
        .unwrap();

        let mut blob = vec![1u8];
        blob.extend_from_slice(&compressed);
        check!(decode(&blob, 44).unwrap() == b"the quick brown fox jumps over the lazy dog");
    }

    #[test]
    fn decode_of_legacy_custom_round_trips_a_known_stream() {
        let options = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
        let stream = liblzma::stream::Stream::new_lzma_encoder(&options).unwrap();
        let mut compressed = Vec::new();
        liblzma::read::XzEncoder::new_stream(&b"legacy lzma payload"[..], stream)
            .read_to_end(&mut compressed)
            .unwrap();

        let mut blob = vec![255u8];
        blob.extend_from_slice(&compressed);
        check!(decode(&blob, 19).unwrap() == b"legacy lzma payload");
    }

    /// Builds a raw LZMA1 blob in the same 5-byte-header shape id 3 uses in
    /// real `CFS0003` archives: 1 properties byte, 4-byte little-endian
    /// dictionary size, then a raw stream with no size field or end marker.
    fn raw_lzma1(payload: &[u8]) -> Vec<u8> {
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

        let mut blob = vec![0x5Du8]; // lc=3, lp=0, pb=2: the preset's defaults
        blob.extend_from_slice(&dict_size.to_le_bytes());
        blob.extend_from_slice(&compressed);
        blob
    }

    #[test]
    fn decode_of_lzma_round_trips_a_known_stream() {
        let compressed = raw_lzma1(b"lzma payload");
        let mut blob = vec![3u8];
        blob.extend_from_slice(&compressed);
        check!(decode(&blob, 12).unwrap() == b"lzma payload");
    }

    #[test]
    fn decode_with_lzma_round_trips_without_a_leading_byte() {
        let compressed = raw_lzma1(b"externally-coded payload");
        check!(decode_with(Codec::Lzma, &compressed, 25).unwrap() == b"externally-coded payload");
    }

    /// A raw LZMA1 stream has no end-of-stream marker: without bounding the
    /// read to the blob's own declared size, `liblzma`'s `Read` wrapper hits
    /// its internal buffer boundary partway through a large payload and
    /// errors instead of reporting completion. Small payloads that fit in
    /// one internal read don't exercise this path.
    #[test]
    fn decode_of_lzma_round_trips_a_stream_larger_than_one_internal_buffer() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let compressed = raw_lzma1(&payload);
        check!(decode_with(Codec::Lzma, &compressed, payload.len()).unwrap() == payload);
    }

    #[test]
    fn decode_with_stored_is_identity() {
        check!(decode_with(Codec::Stored, b"payload bytes", 13).unwrap() == b"payload bytes");
    }

    #[test]
    fn decode_of_modern_custom_reports_unavailable() {
        let blob = vec![254u8, 0, 1, 2, 3];
        let err = decode(&blob, 3).unwrap_err();
        check!(matches!(
            err,
            crate::Error::CodecUnavailable { id: 254, .. }
        ));
    }

    #[cfg(feature = "codec-bzip2")]
    #[test]
    fn decode_of_bzip2_round_trips_a_known_stream() {
        let mut compressed = Vec::new();
        bzip2::read::BzEncoder::new(
            &b"the quick brown fox jumps over the lazy dog"[..],
            bzip2::Compression::default(),
        )
        .read_to_end(&mut compressed)
        .unwrap();

        let mut blob = vec![2u8];
        blob.extend_from_slice(&compressed);
        check!(decode(&blob, 44).unwrap() == b"the quick brown fox jumps over the lazy dog");
    }

    #[cfg(feature = "codec-bzip2")]
    #[test]
    fn decode_with_bzip2_round_trips_without_a_leading_byte() {
        let mut compressed = Vec::new();
        bzip2::read::BzEncoder::new(
            &b"externally-coded payload"[..],
            bzip2::Compression::default(),
        )
        .read_to_end(&mut compressed)
        .unwrap();

        check!(decode_with(Codec::Bzip2, &compressed, 25).unwrap() == b"externally-coded payload");
    }

    #[cfg(not(feature = "codec-bzip2"))]
    #[test]
    fn decode_of_bzip2_reports_unavailable_when_feature_off() {
        let blob = vec![2u8, 0, 1, 2, 3];
        let err = decode(&blob, 3).unwrap_err();
        check!(matches!(err, crate::Error::CodecUnavailable { id: 2, .. }));
    }

    #[cfg(feature = "codec-zstd")]
    #[test]
    fn decode_of_zstd_round_trips_a_known_stream() {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder
            .write_all(b"the quick brown fox jumps over the lazy dog")
            .unwrap();
        let compressed = encoder.finish().unwrap();

        let mut blob = vec![4u8];
        blob.extend_from_slice(&compressed);
        check!(decode(&blob, 44).unwrap() == b"the quick brown fox jumps over the lazy dog");
    }

    #[cfg(feature = "codec-zstd")]
    #[test]
    fn decode_with_zstd_round_trips_without_a_leading_byte() {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.write_all(b"externally-coded payload").unwrap();
        let compressed = encoder.finish().unwrap();

        check!(decode_with(Codec::Zstd, &compressed, 25).unwrap() == b"externally-coded payload");
    }

    #[cfg(not(feature = "codec-zstd"))]
    #[test]
    fn decode_of_zstd_reports_unavailable_when_feature_off() {
        let blob = vec![4u8, 0, 1, 2, 3];
        let err = decode(&blob, 3).unwrap_err();
        check!(matches!(err, crate::Error::CodecUnavailable { id: 4, .. }));
    }

    #[cfg(feature = "codec-brotli")]
    #[test]
    fn decode_of_brotli_round_trips_a_known_stream() {
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 9, 22);
        encoder
            .write_all(b"the quick brown fox jumps over the lazy dog")
            .unwrap();
        let compressed = encoder.into_inner();

        let mut blob = vec![5u8];
        blob.extend_from_slice(&compressed);
        check!(decode(&blob, 44).unwrap() == b"the quick brown fox jumps over the lazy dog");
    }

    #[cfg(feature = "codec-brotli")]
    #[test]
    fn decode_with_brotli_round_trips_without_a_leading_byte() {
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 9, 22);
        encoder.write_all(b"externally-coded payload").unwrap();
        let compressed = encoder.into_inner();

        check!(decode_with(Codec::Brotli, &compressed, 25).unwrap() == b"externally-coded payload");
    }

    #[cfg(not(feature = "codec-brotli"))]
    #[test]
    fn decode_of_brotli_reports_unavailable_when_feature_off() {
        let blob = vec![5u8, 0, 1, 2, 3];
        let err = decode(&blob, 3).unwrap_err();
        check!(matches!(err, crate::Error::CodecUnavailable { id: 5, .. }));
    }

    #[test]
    fn decode_of_an_empty_blob_errors() {
        check!(let Err(crate::Error::EmptyBlob) = decode(&[], 0));
    }

    #[test]
    fn decode_of_an_unknown_id_errors() {
        check!(let Err(crate::Error::UnknownCodec { id: 42 }) = decode(&[42, 1, 2], 1));
    }
}
