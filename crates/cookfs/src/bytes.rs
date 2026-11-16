//! Bounds-checked reads over a decoded blob.
//!
//! Every count a blob supplies passes through [`Reader::check_count`] before
//! anything reserves capacity for it, so a corrupt count fails as an overrun
//! instead of reaching the allocator.

use snafu::{Snafu, ensure};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// A read that ran past the end of a blob.
#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)), visibility(pub(crate)))]
#[non_exhaustive]
pub enum BytesError {
    /// A read wanted more bytes than remain.
    #[snafu(display("read of {want} bytes at {at} overruns a {len}-byte blob"))]
    Overrun {
        /// Offset the read started at.
        at: usize,
        /// Bytes the read needed, saturated at `usize::MAX` when a count overflowed.
        want: usize,
        /// Length of the blob.
        len: usize,
    },
}

const _: () = assert!(size_of::<BytesError>() <= 64);

/// A cursor over one decoded blob.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Accepts `count` records of `record` bytes only if that many bytes remain.
    pub(crate) fn check_count(&self, count: u32, record: usize) -> Result<usize, BytesError> {
        let count = count as usize;
        let want = count.saturating_mul(record);
        ensure!(
            want <= self.remaining(),
            bytes_error::Overrun {
                at: self.pos,
                want,
                len: self.data.len()
            }
        );
        Ok(count)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], BytesError> {
        ensure!(
            len <= self.remaining(),
            bytes_error::Overrun {
                at: self.pos,
                want: len,
                len: self.data.len()
            }
        );
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, BytesError> {
        Ok(self.take(1)?[0])
    }

    /// One fixed-layout record, cast in place.
    pub(crate) fn record<T: FromBytes + KnownLayout + Immutable + Unaligned>(
        &mut self,
    ) -> Result<&'a T, BytesError> {
        let at = self.pos;
        let bytes = self.take(size_of::<T>())?;
        T::ref_from_bytes(bytes).ok().ok_or(BytesError::Overrun {
            at,
            want: size_of::<T>(),
            len: self.data.len(),
        })
    }

    /// `count` fixed-layout records, cast in place after the count is checked.
    pub(crate) fn records<T: FromBytes + Immutable + Unaligned>(
        &mut self,
        count: u32,
    ) -> Result<&'a [T], BytesError> {
        let at = self.pos;
        let count = self.check_count(count, size_of::<T>())?;
        let bytes = self.take(count * size_of::<T>())?;
        <[T]>::ref_from_bytes(bytes)
            .ok()
            .ok_or(BytesError::Overrun {
                at,
                want: bytes.len(),
                len: self.data.len(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::{assert, check};
    use rstest::rstest;

    /// A count whose byte size overflows saturates rather than wrapping.
    #[rstest]
    #[case::larger_than_the_blob(4, 4, 16)]
    #[case::byte_size_overflows(u32::MAX, usize::MAX, usize::MAX)]
    fn a_count_the_blob_cannot_hold_fails_before_any_allocation(
        #[case] count: u32,
        #[case] size: usize,
        #[case] want: usize,
    ) {
        let blob = [0u8; 8];
        let r = Reader::new(&blob);
        assert!(let Err(BytesError::Overrun { want: got, .. }) = r.check_count(count, size));
        check!(got == want);
    }
}
