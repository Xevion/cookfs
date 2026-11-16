//! Reading one file's contents, whole or as a stream.

use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;

use positioned_io::{ReadAt, Size};
use snafu::ensure;

use crate::cache::Page;
use crate::error::error as ctx;
use crate::index::Block;
use crate::{Archive, Result};

/// A file's contents as a [`Read`] + [`Seek`] stream, decoding pages only as it reaches them.
///
/// Unlike [`Archive::read`], a stream is not bounded by
/// [`crate::Limits::max_file_len`], since it never holds the whole file.
/// It holds the page under its position, and the archive's cache keeps
/// recent pages for other readers.
pub struct FileReader<'a, R> {
    archive: &'a Archive<R>,
    blocks: &'a [Block],
    /// Where in the file each block starts, strictly increasing since no block is empty.
    starts: Vec<u64>,
    size: u64,
    pos: u64,
    held: Option<(u32, Page)>,
    /// Decoded page bytes fetched since the last seek, and the most an in-order read may need.
    decoded: u64,
    budget: u64,
}

impl<R> std::fmt::Debug for FileReader<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileReader")
            .field("size", &self.size)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<'a, R: ReadAt + Size> FileReader<'a, R> {
    pub(crate) fn new(archive: &'a Archive<R>, blocks: &'a [Block]) -> Self {
        let mut at = 0u64;
        let starts = blocks
            .iter()
            .map(|b| {
                let start = at;
                at += u64::from(b.size);
                start
            })
            .collect();
        let mut reader = Self {
            archive,
            blocks,
            starts,
            size: at,
            pos: 0,
            held: None,
            decoded: 0,
            budget: 0,
        };
        reader.reset_budget();
        reader
    }

    /// The file's size in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.size
    }

    /// Whether the file is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// A file read in order from here wastes at most the unused parts of its first and last pages.
    fn reset_budget(&mut self) {
        self.decoded = 0;
        let pages = 2 * self.archive.limits.max_page_len as u64;
        self.budget = (self.size - self.pos.min(self.size)).saturating_add(pages);
    }

    /// The bytes from the position to the end of its block, without advancing.
    pub(crate) fn chunk(&mut self) -> Result<Option<(Page, Range<usize>)>> {
        if self.pos >= self.size {
            return Ok(None);
        }
        let i = self.starts.partition_point(|&s| s <= self.pos) - 1;
        let Block { page, offset, size } = self.blocks[i];
        let data = self.page(page)?;
        let within = (self.pos - self.starts[i]) as usize;
        let end = offset as usize + size as usize;
        ensure!(
            end <= data.len(),
            ctx::BlockOutOfPage {
                page,
                offset,
                size,
                page_len: data.len(),
            }
        );
        Ok(Some((data, offset as usize + within..end)))
    }

    pub(crate) fn advance(&mut self, n: usize) {
        self.pos += n as u64;
    }

    fn page(&mut self, n: u32) -> Result<Page> {
        if let Some((held, data)) = &self.held
            && *held == n
        {
            return Ok(data.clone());
        }
        let data = self.archive.page(n)?;
        self.decoded += data.len() as u64;
        ensure!(
            self.decoded <= self.budget,
            ctx::Overdecoded {
                size: self.size,
                decoded: self.decoded,
            }
        );
        self.held = Some((n, data.clone()));
        Ok(data)
    }
}

/// A failure surfaces as an [`io::Error`] wrapping the crate's [`crate::Error`], which
/// `io::Error::downcast` recovers.
impl<R: ReadAt + Size> Read for FileReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some((data, range)) = self.chunk().map_err(io::Error::other)? else {
            return Ok(0);
        };
        let n = range.len().min(buf.len());
        buf[..n].copy_from_slice(&data[range.start..range.start + n]);
        self.advance(n);
        Ok(n)
    }
}

impl<R: ReadAt + Size> Seek for FileReader<'_, R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(delta) => self.size.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        };
        let Some(target) = target else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the file",
            ));
        };
        self.pos = target;
        self.reset_budget();
        Ok(target)
    }
}
