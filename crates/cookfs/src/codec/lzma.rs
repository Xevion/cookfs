//! The two LZMA1 container shapes: `.lzma`-alone and `CFS0003`'s headerless raw stream.

use snafu::{ResultExt, ensure};

use super::stream::{Step, drain};
use super::{DecodeError, decode_error};
use crate::wire::Compression;

/// Feeds an LZMA stream from `parts` in order, one decoder step at a time.
fn lzma_step<'a>(
    stream: &'a mut liblzma::stream::Stream,
    parts: [&'a [u8]; 2],
) -> impl FnMut(&mut Vec<u8>) -> std::io::Result<Step> + 'a {
    move |out| {
        let consumed = usize::try_from(stream.total_in()).unwrap_or(usize::MAX);
        let input = consumed.checked_sub(parts[0].len()).map_or_else(
            || &parts[0][consumed..],
            |into_second| parts[1].get(into_second..).unwrap_or_default(),
        );
        let status = stream
            .process_vec(input, out, liblzma::stream::Action::Run)
            .map_err(std::io::Error::other)?;
        Ok(match status {
            liblzma::stream::Status::StreamEnd => Step::Done,
            liblzma::stream::Status::MemNeeded => Step::Starved,
            _ => Step::Going,
        })
    }
}

/// BitRock's legacy custom slot: a classic `.lzma`-alone stream, whose 13-byte header the decoder reads itself.
pub(super) fn lzma_alone(
    id: Compression,
    body: &[u8],
    limit: usize,
) -> Result<Vec<u8>, DecodeError> {
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

    let mut stream = liblzma::stream::Stream::new_lzma_decoder(u64::MAX)
        .map_err(std::io::Error::other)
        .context(decode_error::Decompress { id })?;
    let target = limit.saturating_add(1);
    let out = drain(
        id,
        body.len(),
        output,
        target,
        lzma_step(&mut stream, [&header[..split], &body[split..]]),
    )?;
    ensure!(out.len() <= limit, decode_error::TooLarge { id, limit });
    Ok(out)
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
/// input runs out, so the declared size is the only place to stop.
pub(super) fn raw_lzma1(
    id: Compression,
    body: &[u8],
    declared: usize,
) -> Result<Vec<u8>, DecodeError> {
    const HEADER_LEN: usize = 5;
    let (header, payload) = body.split_at(HEADER_LEN.min(body.len()));
    let mut header = header.to_vec();
    clamp_dictionary(&mut header, declared);

    let mut filters = liblzma::stream::Filters::new();
    filters
        .lzma1_properties(&header)
        .map_err(std::io::Error::other)
        .context(decode_error::Decompress { id })?;
    let mut stream = liblzma::stream::Stream::new_raw_decoder(&filters)
        .map_err(std::io::Error::other)
        .context(decode_error::Decompress { id })?;
    drain(
        id,
        body.len(),
        declared,
        declared,
        lzma_step(&mut stream, [payload, &[]]),
    )
}

#[cfg(test)]
mod tests {
    use super::super::decode;
    use super::super::testing::{TEXT, exact, lzma_alone_stream, raw_lzma1_stream};
    use crate::wire::Compression;
    use assert2::check;

    /// The decoder's internal buffer boundary falls inside a large payload,
    /// which only the declared-size stop gets past.
    #[test]
    fn raw_lzma1_decodes_past_one_internal_buffer() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let body = raw_lzma1_stream(&payload);
        check!(decode(Compression::LZMA, &body, exact(payload.len())).unwrap() == payload);
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
}
