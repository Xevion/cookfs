//! Decompression of page, pgindex and fsindex blobs.

use std::io::Read;

use snafu::{ResultExt, Snafu, ensure};

use crate::parsers::cfs0002::LEGACY_CODECS;
use crate::wire::Compression;

/// A blob that could not be decoded.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum CodecError {
    /// The id names no codec this crate knows.
    #[snafu(display("unknown compression id {}", id.raw()))]
    Unknown {
        /// The id as read.
        id: Compression,
    },
    /// The codec is known but cannot be decoded by this build.
    #[snafu(display("{id} decoding is not available: {why}"))]
    Unavailable {
        /// The codec.
        id: Compression,
        /// What would make it available.
        why: &'static str,
    },
    /// A `CFS0002` blob had no leading id byte.
    #[snafu(display("blob is empty, so it has no compression id"))]
    Empty,
    /// A legacy bzip2 blob ends before the decoded size it must carry.
    #[snafu(display("bzip2 blob is too short to hold its size prefix"))]
    NoSizePrefix,
    /// The codec rejected the payload.
    #[snafu(display("{id} payload failed to decode"))]
    Decompress {
        /// The codec.
        id: Compression,
        /// The decoder's failure.
        source: std::io::Error,
    },
    /// The output would exceed its declared size or the configured limit.
    #[snafu(display("{id} output exceeds {limit} bytes"))]
    TooLarge {
        /// The codec.
        id: Compression,
        /// The ceiling that was hit.
        limit: usize,
    },
    /// The output stopped short of the size the archive declared for it.
    #[snafu(display("{id} output is {got} bytes, the archive declares {want}"))]
    Short {
        /// The codec.
        id: Compression,
        /// The declared size.
        want: usize,
        /// The size actually produced.
        got: usize,
    },
    /// Raw LZMA1 has no end marker, so it cannot be decoded without a declared size.
    #[snafu(display("{id} blob has no declared size to stop at"))]
    Unbounded {
        /// The codec.
        id: Compression,
    },
}

const _: () = assert!(size_of::<CodecError>() <= 64);

/// How large a decoded blob may be.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Expect {
    /// The size the archive records for the decoded blob, when it records one.
    pub(crate) declared: Option<usize>,
    /// The configured ceiling, applied whether or not a size is declared.
    pub(crate) limit: usize,
}

/// Decodes a `CFS0002` blob, whose first byte names its codec.
///
/// Legacy bzip2 blobs also carry the decoded size, as a big-endian `u32`
/// between the id byte and the stream.
pub(crate) fn decode_prefixed(blob: &[u8], expect: Expect) -> Result<Vec<u8>, CodecError> {
    let (&id, body) = blob.split_first().ok_or(CodecError::Empty)?;
    let id = Compression::from_raw(id);
    ensure!(LEGACY_CODECS.contains(&id), codec_error::Unknown { id });
    if id == Compression::BZIP2 {
        let (size, stream) = body
            .split_first_chunk::<4>()
            .ok_or(CodecError::NoSizePrefix)?;
        let expect = Expect {
            declared: expect
                .declared
                .or_else(|| Some(u32::from_be_bytes(*size) as usize)),
            ..expect
        };
        return decode(id, stream, expect);
    }
    decode(id, body, expect)
}

/// Decodes a `CFS0003` blob, whose codec a table names; BitRock's legacy slot is not among them.
pub(crate) fn decode_external(
    id: Compression,
    body: &[u8],
    expect: Expect,
) -> Result<Vec<u8>, CodecError> {
    ensure!(
        id != Compression::LEGACY_CUSTOM,
        codec_error::Unknown { id }
    );
    // Upstream never decodes a `CFS0003` page declared empty, whatever its codec.
    if expect.declared == Some(0) {
        return Ok(Vec::new());
    }
    decode(id, body, expect)
}

/// Decodes a payload whose codec is named out of band.
pub(crate) fn decode(id: Compression, body: &[u8], expect: Expect) -> Result<Vec<u8>, CodecError> {
    let ceiling = match expect.declared {
        Some(declared) => {
            ensure!(
                declared <= expect.limit,
                codec_error::TooLarge {
                    id,
                    limit: expect.limit
                }
            );
            declared
        }
        None => expect.limit,
    };

    let out = match id {
        Compression::NONE => {
            ensure!(
                body.len() <= ceiling,
                codec_error::TooLarge { id, limit: ceiling }
            );
            body.to_vec()
        }
        Compression::ZLIB => bounded(id, flate2::read::DeflateDecoder::new(body), ceiling)?,
        Compression::LZMA => {
            let declared = expect.declared.ok_or(CodecError::Unbounded { id })?;
            raw_lzma1(id, body, declared)?
        }
        Compression::LEGACY_CUSTOM => lzma_alone(id, body, ceiling)?,
        Compression::BZIP2 => bzip2(id, body, ceiling)?,
        Compression::ZSTD => zstd(id, body, ceiling)?,
        Compression::BROTLI => brotli(id, body, ceiling)?,
        Compression::CUSTOM => {
            return codec_error::Unavailable {
                id,
                why: "it is a Tcl callback slot",
            }
            .fail();
        }
        id => return codec_error::Unknown { id }.fail(),
    };

    if let Some(want) = expect.declared {
        ensure!(
            out.len() == want,
            codec_error::Short {
                id,
                want,
                got: out.len()
            }
        );
    }
    Ok(out)
}

/// Reads a decoder to its end, failing rather than truncating past `limit`.
///
/// `take(limit)` alone stops at the ceiling and reports the truncated output
/// as clean, which lets an oversized stream through. Taking one byte more and
/// refusing it turns the ceiling into an error.
fn bounded(id: Compression, reader: impl Read, limit: usize) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut out)
        .context(codec_error::Decompress { id })?;
    ensure!(out.len() <= limit, codec_error::TooLarge { id, limit });
    Ok(out)
}

#[cfg(feature = "codec-bzip2")]
fn bzip2(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
    bounded(id, bzip2::read::BzDecoder::new(body), limit)
}

#[cfg(not(feature = "codec-bzip2"))]
fn bzip2(id: Compression, _: &[u8], _: usize) -> Result<Vec<u8>, CodecError> {
    codec_error::Unavailable {
        id,
        why: "the `codec-bzip2` feature is off",
    }
    .fail()
}

#[cfg(feature = "codec-zstd")]
fn zstd(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
    let decoder = zstd::stream::read::Decoder::new(body).context(codec_error::Decompress { id })?;
    bounded(id, decoder, limit)
}

#[cfg(not(feature = "codec-zstd"))]
fn zstd(id: Compression, _: &[u8], _: usize) -> Result<Vec<u8>, CodecError> {
    codec_error::Unavailable {
        id,
        why: "the `codec-zstd` feature is off",
    }
    .fail()
}

#[cfg(feature = "codec-brotli")]
fn brotli(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
    const BUFFER: usize = 4096;
    bounded(id, brotli::Decompressor::new(body, BUFFER), limit)
}

#[cfg(not(feature = "codec-brotli"))]
fn brotli(id: Compression, _: &[u8], _: usize) -> Result<Vec<u8>, CodecError> {
    codec_error::Unavailable {
        id,
        why: "the `codec-brotli` feature is off",
    }
    .fail()
}

/// BitRock's legacy custom slot: a classic `.lzma`-alone stream, whose 13-byte header the decoder reads itself.
fn lzma_alone(id: Compression, body: &[u8], limit: usize) -> Result<Vec<u8>, CodecError> {
    const HEADER_LEN: usize = 13;
    let split = HEADER_LEN.min(body.len());
    let mut header = [0u8; HEADER_LEN];
    header[..split].copy_from_slice(&body[..split]);
    // The header may record the decoded size, which bounds the dictionary tighter than the limit.
    let recorded = u64::from_le_bytes([
        header[5], header[6], header[7], header[8], header[9], header[10], header[11], header[12],
    ]);
    let output = usize::try_from(recorded).map_or(limit, |n| n.min(limit));
    clamp_dictionary(&mut header, output);

    let stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)
        .map_err(std::io::Error::other)
        .context(codec_error::Decompress { id })?;
    let input = header[..split].chain(&body[split..]);
    bounded(
        id,
        liblzma::read::XzDecoder::new_stream(input, stream),
        limit,
    )
}

/// Lowers an LZMA header's dictionary size to `limit` bytes of output.
///
/// The decoder allocates the whole declared dictionary up front, so a crafted
/// header asking for 4 GiB aborts in the allocator. A match can only reach
/// back over bytes already decoded, so a dictionary larger than the output is
/// never used and clamping it changes nothing a valid stream decodes to.
fn clamp_dictionary(header: &mut [u8], limit: usize) {
    const MIN_DICTIONARY: u32 = 4096;
    let Some(dict) = header.get_mut(1..5) else {
        return;
    };
    let declared = u32::from_le_bytes([dict[0], dict[1], dict[2], dict[3]]);
    let ceiling = u32::try_from(limit).unwrap_or(u32::MAX).max(MIN_DICTIONARY);
    dict.copy_from_slice(&declared.min(ceiling).to_le_bytes());
}

/// `CFS0003`'s raw LZMA1: a properties byte and a little-endian dictionary size, then a stream with no end marker.
///
/// Without an end marker the decoder never reports a clean end and errors once
/// input runs out, so the declared size is the only place to stop. Reading one
/// byte past it, as [`bounded`] does, would run the decoder into that error.
fn raw_lzma1(id: Compression, body: &[u8], declared: usize) -> Result<Vec<u8>, CodecError> {
    const HEADER_LEN: usize = 5;
    let (header, payload) = body.split_at(HEADER_LEN.min(body.len()));
    let mut header = header.to_vec();
    clamp_dictionary(&mut header, declared);

    let mut filters = liblzma::stream::Filters::new();
    filters
        .lzma1_properties(&header)
        .map_err(std::io::Error::other)
        .context(codec_error::Decompress { id })?;
    let stream = liblzma::stream::Stream::new_raw_decoder(&filters)
        .map_err(std::io::Error::other)
        .context(codec_error::Decompress { id })?;

    let mut out = Vec::new();
    liblzma::read::XzDecoder::new_stream(payload, stream)
        .take(declared as u64)
        .read_to_end(&mut out)
        .context(codec_error::Decompress { id })?;
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use assert2::check;
    use rstest::rstest;
    use std::io::Write;

    const TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog";

    fn exact(len: usize) -> Expect {
        Expect {
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
    pub(crate) fn zstd_stream(payload: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    #[cfg(feature = "codec-brotli")]
    pub(crate) fn brotli_stream(payload: &[u8]) -> Vec<u8> {
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 9, 22);
        encoder.write_all(payload).unwrap();
        encoder.into_inner()
    }

    #[rstest]
    #[case::none(Compression::NONE, TEXT.to_vec())]
    #[case::zlib(Compression::ZLIB, deflate(TEXT))]
    #[case::lzma(Compression::LZMA, raw_lzma1_stream(TEXT))]
    #[case::legacy_custom(Compression::LEGACY_CUSTOM, lzma_alone_stream(TEXT))]
    #[cfg_attr(
        feature = "codec-bzip2",
        case::bzip2(Compression::BZIP2, bzip2_stream(TEXT))
    )]
    #[cfg_attr(
        feature = "codec-zstd",
        case::zstd(Compression::ZSTD, zstd_stream(TEXT))
    )]
    #[cfg_attr(
        feature = "codec-brotli",
        case::brotli(Compression::BROTLI, brotli_stream(TEXT))
    )]
    fn each_codec_decodes_a_stream_its_reference_encoder_wrote(
        #[case] id: Compression,
        #[case] body: Vec<u8>,
    ) {
        check!(decode(id, &body, exact(TEXT.len())).unwrap() == TEXT);
    }

    #[test]
    fn a_prefixed_blob_names_its_codec_in_its_first_byte() {
        let mut blob = vec![1u8];
        blob.extend_from_slice(&deflate(TEXT));
        check!(decode_prefixed(&blob, exact(TEXT.len())).unwrap() == TEXT);
    }

    #[cfg(feature = "codec-bzip2")]
    #[test]
    fn a_legacy_bzip2_blob_carries_its_size_before_the_stream() {
        let mut blob = vec![2u8];
        blob.extend_from_slice(&(TEXT.len() as u32).to_be_bytes());
        blob.extend_from_slice(&bzip2_stream(TEXT));
        let expect = Expect {
            declared: None,
            limit: 1 << 20,
        };
        check!(decode_prefixed(&blob, expect).unwrap() == TEXT);
    }

    /// The decoder's internal buffer boundary falls inside a large payload,
    /// which only the declared-size stop gets past.
    #[test]
    fn raw_lzma1_decodes_past_one_internal_buffer() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let body = raw_lzma1_stream(&payload);
        check!(decode(Compression::LZMA, &body, exact(payload.len())).unwrap() == payload);
    }

    #[test]
    fn raw_lzma1_without_a_declared_size_is_refused() {
        let body = raw_lzma1_stream(TEXT);
        let expect = Expect {
            declared: None,
            limit: 1 << 20,
        };
        check!(let Err(CodecError::Unbounded { .. }) = decode(Compression::LZMA, &body, expect));
    }

    #[test]
    fn output_past_the_limit_is_an_error_not_a_truncation() {
        let expect = Expect {
            declared: None,
            limit: 4,
        };
        check!(let Err(CodecError::TooLarge { limit: 4, .. }) = decode(Compression::ZLIB, &deflate(TEXT), expect));
    }

    #[test]
    fn output_past_its_declared_size_is_an_error() {
        check!(let Err(CodecError::TooLarge { limit: 4, .. }) = decode(Compression::ZLIB, &deflate(TEXT), exact(4)));
    }

    #[test]
    fn output_short_of_its_declared_size_is_an_error() {
        let got = decode(Compression::ZLIB, &deflate(TEXT), exact(TEXT.len() + 1));
        check!(let Err(CodecError::Short { got: 43, want: 44, .. }) = got);
    }

    #[test]
    fn a_declared_size_above_the_limit_is_refused_before_decoding() {
        let expect = Expect {
            declared: Some(100),
            limit: 10,
        };
        check!(let Err(CodecError::TooLarge { limit: 10, .. }) = decode(Compression::NONE, &[0; 100], expect));
    }

    #[rstest]
    #[case::unknown(Compression::from_raw(42))]
    #[case::custom(Compression::CUSTOM)]
    fn an_id_without_a_decoder_is_refused(#[case] id: Compression) {
        check!(decode(id, &[1, 2, 3], exact(3)).is_err());
    }

    /// Found by the `archive` fuzz target: a 4 GiB dictionary was allocated before any byte decoded.
    #[test]
    fn a_huge_declared_dictionary_is_clamped_to_the_output() {
        let mut body = lzma_alone_stream(TEXT);
        body[1..5].copy_from_slice(&0xFFFF_FFBFu32.to_le_bytes());
        check!(decode(Compression::LEGACY_CUSTOM, &body, exact(TEXT.len())).unwrap() == TEXT);

        let mut body = raw_lzma1_stream(TEXT);
        body[1..5].copy_from_slice(&0xFFFF_FFBFu32.to_le_bytes());
        check!(decode(Compression::LZMA, &body, exact(TEXT.len())).unwrap() == TEXT);
    }

    #[test]
    fn a_page_declared_empty_is_empty_without_decoding() {
        check!(
            decode_external(Compression::LZMA, &[], exact(0))
                .unwrap()
                .is_empty()
        );
    }

    #[rstest]
    #[case::zstd_in_a_legacy_blob(decode_prefixed(&[4, 0, 0], exact(1)))]
    #[case::legacy_lzma_in_a_cfs0003_blob(decode_external(Compression::LEGACY_CUSTOM, &[0], exact(1)))]
    fn a_codec_the_format_cannot_name_is_unknown(#[case] got: Result<Vec<u8>, CodecError>) {
        check!(let Err(CodecError::Unknown { .. }) = got);
    }

    #[test]
    fn an_empty_prefixed_blob_has_no_id() {
        check!(let Err(CodecError::Empty) = decode_prefixed(&[], exact(0)));
    }
}
