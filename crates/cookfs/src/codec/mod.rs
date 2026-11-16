//! Decompression of page, pgindex and fsindex blobs.

mod error;
mod lzma;
mod optional;
mod stream;
#[cfg(test)]
pub(crate) mod testing;

use std::io::Read;

use snafu::{ResultExt, ensure};

pub use error::DecodeError;
pub(crate) use error::decode_error;

use crate::wire::Compression;

/// The codecs a `CFS0002` blob can name; the legacy writer knows no others.
pub(crate) const LEGACY_CODECS: [Compression; 4] = [
    Compression::NONE,
    Compression::ZLIB,
    Compression::BZIP2,
    Compression::LEGACY_CUSTOM,
];

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
pub(crate) fn decode_prefixed(blob: &[u8], expect: Expect) -> Result<Vec<u8>, DecodeError> {
    let (&id, body) = blob.split_first().ok_or(DecodeError::Empty)?;
    let id = Compression::from_raw(id);
    ensure!(LEGACY_CODECS.contains(&id), decode_error::Unknown { id });
    if id == Compression::BZIP2 {
        let (size, stream) = body
            .split_first_chunk::<4>()
            .ok_or(DecodeError::NoSizePrefix)?;
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
) -> Result<Vec<u8>, DecodeError> {
    ensure!(
        id != Compression::LEGACY_CUSTOM,
        decode_error::Unknown { id }
    );
    // Upstream never decodes a `CFS0003` page declared empty, whatever its codec.
    if expect.declared == Some(0) {
        return Ok(Vec::new());
    }
    decode(id, body, expect)
}

/// Decodes a payload whose codec is named out of band.
pub(crate) fn decode(id: Compression, body: &[u8], expect: Expect) -> Result<Vec<u8>, DecodeError> {
    let ceiling = match expect.declared {
        Some(declared) => {
            ensure!(
                declared <= expect.limit,
                decode_error::TooLarge {
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
                decode_error::TooLarge { id, limit: ceiling }
            );
            body.to_vec()
        }
        Compression::ZLIB => stream::deflate(id, body, ceiling, expect.declared)?,
        Compression::LZMA => {
            let declared = expect.declared.ok_or(DecodeError::Unbounded { id })?;
            lzma::raw_lzma1(id, body, declared)?
        }
        Compression::LEGACY_CUSTOM => lzma::lzma_alone(id, body, ceiling)?,
        Compression::BZIP2 => optional::bzip2(id, body, ceiling)?,
        Compression::ZSTD => optional::zstd(id, body, ceiling)?,
        Compression::BROTLI => optional::brotli(id, body, ceiling)?,
        Compression::CUSTOM => {
            return decode_error::Unavailable {
                id,
                why: "it is a Tcl callback slot",
            }
            .fail();
        }
        id => return decode_error::Unknown { id }.fail(),
    };

    if let Some(want) = expect.declared {
        ensure!(
            out.len() == want,
            decode_error::Short {
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
fn bounded(id: Compression, reader: impl Read, limit: usize) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut out)
        .context(decode_error::Decompress { id })?;
    ensure!(out.len() <= limit, decode_error::TooLarge { id, limit });
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "codec-brotli")]
    use super::testing::brotli_stream;
    #[cfg(feature = "codec-bzip2")]
    use super::testing::bzip2_stream;
    #[cfg(feature = "codec-zstd")]
    use super::testing::zstd_stream;
    use super::testing::{TEXT, deflate, exact, lzma_alone_stream, raw_lzma1_stream};
    use super::*;
    use assert2::check;
    use rstest::rstest;

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

    #[test]
    fn raw_lzma1_without_a_declared_size_is_refused() {
        let body = raw_lzma1_stream(TEXT);
        let expect = Expect {
            declared: None,
            limit: 1 << 20,
        };
        check!(let Err(DecodeError::Unbounded { .. }) = decode(Compression::LZMA, &body, expect));
    }

    #[test]
    fn output_past_the_limit_is_an_error_not_a_truncation() {
        let expect = Expect {
            declared: None,
            limit: 4,
        };
        check!(let Err(DecodeError::TooLarge { limit: 4, .. }) = decode(Compression::ZLIB, &deflate(TEXT), expect));
    }

    #[test]
    fn output_past_its_declared_size_is_an_error() {
        check!(let Err(DecodeError::TooLarge { limit: 4, .. }) = decode(Compression::ZLIB, &deflate(TEXT), exact(4)));
    }

    #[test]
    fn output_short_of_its_declared_size_is_an_error() {
        let got = decode(Compression::ZLIB, &deflate(TEXT), exact(TEXT.len() + 1));
        check!(let Err(DecodeError::Short { got: 43, want: 44, .. }) = got);
    }

    #[test]
    fn a_declared_size_above_the_limit_is_refused_before_decoding() {
        let expect = Expect {
            declared: Some(100),
            limit: 10,
        };
        check!(let Err(DecodeError::TooLarge { limit: 10, .. }) = decode(Compression::NONE, &[0; 100], expect));
    }

    #[rstest]
    #[case::unknown(Compression::from_raw(42))]
    #[case::custom(Compression::CUSTOM)]
    fn an_id_without_a_decoder_is_refused(#[case] id: Compression) {
        check!(decode(id, &[1, 2, 3], exact(3)).is_err());
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
    fn a_codec_the_format_cannot_name_is_unknown(#[case] got: Result<Vec<u8>, DecodeError>) {
        check!(let Err(DecodeError::Unknown { .. }) = got);
    }

    #[test]
    fn an_empty_prefixed_blob_has_no_id() {
        check!(let Err(DecodeError::Empty) = decode_prefixed(&[], exact(0)));
    }
}
