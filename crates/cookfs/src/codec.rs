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
    /// bzip2 (id 2). Not yet decodable by this build.
    Bzip2,
    /// Raw LZMA1 (id 3): `CFS0003`'s own codec, distinct from BitRock's
    /// `.lzma`-alone container at id 255 despite sharing an algorithm.
    Lzma,
    /// Zstandard (id 4). Not yet decodable by this build.
    Zstd,
    /// Brotli (id 5). Not yet decodable by this build.
    Brotli,
    /// BitRock's legacy LZMA-alone codec, wired into the custom slot (id 255).
    LegacyCustom,
    /// The modern custom codec slot (id 254). Not yet decodable by this build.
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
/// `uncompressed_len` is the blob's own declared decompressed size; only
/// [`Codec::Lzma`] needs it, since a raw LZMA1 stream has no end-of-stream
/// marker to decode toward.
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
/// `uncompressed_len` is the blob's own declared decompressed size; only
/// [`Codec::Lzma`] needs it, since a raw LZMA1 stream has no end-of-stream
/// marker to decode toward.
///
/// # Errors
///
/// Returns [`crate::Error::CodecUnavailable`] for a known id this build
/// cannot decode, and [`crate::Error::Decompress`] if the codec's decoder
/// rejects the payload.
pub fn decode_with(codec: Codec, body: &[u8], uncompressed_len: usize) -> Result<Vec<u8>> {
    match codec {
        Codec::Stored => Ok(body.to_vec()),
        Codec::Deflate => decode_deflate(body),
        Codec::Lzma => decode_raw_lzma1(body, uncompressed_len),
        Codec::LegacyCustom => decode_lzma_alone(body),
        codec @ Codec::Bzip2 => unavailable(codec, "bzip2"),
        codec @ Codec::Zstd => unavailable(codec, "zstd"),
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

fn decode_deflate(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(body)
        .read_to_end(&mut out)
        .context(DecompressSnafu { codec: "deflate" })?;
    Ok(out)
}

/// BitRock's legacy custom slot (id 255): the classic `.lzma`-alone
/// container, a 13-byte header (properties, dictionary size, uncompressed
/// size) that `liblzma`'s alone decoder consumes itself.
fn decode_lzma_alone(body: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)
        .map_err(std::io::Error::other)
        .context(DecompressSnafu { codec: "lzma" })?;
    liblzma::read::XzDecoder::new_stream(body, stream)
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
    fn decode_of_unimplemented_codecs_reports_unavailable() {
        for id in [2u8, 4, 5, 254] {
            let blob = vec![id, 0, 1, 2, 3];
            let err = decode(&blob, 3).unwrap_err();
            check!(matches!(err, crate::Error::CodecUnavailable { id: got, .. } if got == id));
        }
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
