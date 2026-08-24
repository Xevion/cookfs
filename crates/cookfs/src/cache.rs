//! Bounded page cache.
//!
//! Pages are handed out as `Arc<[u8]>` so a hit never copies. The policy is LRU
//! with a per-page load gate, chosen from measurements over a corpus of real
//! installers rather than from first principles.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

/// A decompressed page, shared by every reader that asked for it.
pub type Page = Arc<[u8]>;

/// How much the cache may retain, derived from an archive's own page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Resident page count.
    pub pages: usize,
}

impl Budget {
    /// Cache floor and ceiling in bytes.
    ///
    /// A library should not claim hundreds of megabytes without being asked, so
    /// the ceiling is deliberately modest; sequential reads stay optimal well
    /// below it because LRU only needs the page currently being consumed.
    const FLOOR: u64 = 8 << 20;
    const CEILING: u64 = 128 << 20;

    /// Sizes the cache from uncompressed page sizes, which the page table
    /// carries before any page is read.
    ///
    /// Page sizes span two orders of magnitude across real archives (hundreds
    /// of KB in IDA installers, tens of MB in Bitnami stacks), so any fixed
    /// value either thrashes on one shape or wastes memory on the other.
    /// Holding a couple of pages per worker lets each thread own one and still
    /// reuse a neighbour's.
    #[must_use]
    pub fn from_pages(uncompressed: &[u32], workers: usize) -> Self {
        let count = uncompressed.len().max(1);
        let mean = (uncompressed.iter().map(|&s| u64::from(s)).sum::<u64>() / count as u64).max(1);
        let want = (2 * workers as u64 * mean).clamp(Self::FLOOR, Self::CEILING);
        Self {
            // `count.max(2)` keeps the upper bound above the lower one: an
            // archive with a single page (or none) would otherwise clamp with
            // min > max, which panics.
            pages: ((want / mean) as usize).clamp(2, count.max(2)),
        }
    }
}

/// An LRU of pages, where each entry gates concurrent loads of that page.
///
/// Two decisions here were measured, and both reversed an earlier guess.
///
/// LRU rather than a frequency policy: reads scan pages in order, because files
/// are stored and listed in path order. A TinyLFU admission policy (moka) reads
/// that scan as a stream of low-frequency entries and refuses to admit them, so
/// every lookup re-decompresses and a full read of a 35-page archive turns
/// 67,000 lookups into 67,000 decompressions instead of 35.
///
/// The gate is held *across* the load, not merely around the store. Releasing
/// it lets concurrent misses on one page all decompress it, which on a
/// many-files-per-page archive burned fifteen times the CPU to finish slower
/// than a single thread.
#[derive(Debug)]
pub struct PageCache {
    slots: Mutex<LruCache<usize, Arc<Mutex<Option<Page>>>>>,
}

impl PageCache {
    /// Builds a cache holding at most `budget.pages` decompressed pages.
    ///
    /// # Panics
    ///
    /// Never: the capacity is clamped above zero before construction.
    #[must_use]
    pub fn new(budget: Budget) -> Self {
        let cap = NonZeroUsize::new(budget.pages.max(2)).expect("clamped above zero");
        Self {
            slots: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Returns page `n`, calling `load` only if it is not already resident.
    ///
    /// Concurrent callers asking for the same page load it once; callers asking
    /// for different pages never block each other. An evicted page stays alive
    /// for whoever still holds its `Arc`.
    ///
    /// # Errors
    ///
    /// Returns whatever `load` returns. A failed load caches nothing, so a
    /// later call retries.
    pub fn get_or_load<E>(
        &self,
        n: usize,
        load: impl FnOnce() -> Result<Vec<u8>, E>,
    ) -> Result<Page, E> {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert(n, || Arc::new(Mutex::new(None)))
            .clone();

        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(hit) = guard.as_ref() {
            return Ok(hit.clone());
        }
        let page: Page = load()?.into();
        *guard = Some(page.clone());
        drop(guard);
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert2::check;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn page(byte: u8) -> Vec<u8> {
        vec![byte; 8]
    }

    #[test]
    fn a_hit_does_not_call_load_again() {
        let cache = PageCache::new(Budget { pages: 4 });
        let calls = AtomicUsize::new(0);
        let count = || {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok::<_, &str>(page(1))
        };

        check!(cache.get_or_load(0, count).unwrap()[0] == 1);
        check!(cache.get_or_load(0, count).unwrap()[0] == 1);
        check!(calls.load(Ordering::Relaxed) == 1);
    }

    #[test]
    fn a_hit_shares_rather_than_copies() {
        let cache = PageCache::new(Budget { pages: 4 });
        let first = cache.get_or_load(0, || Ok::<_, &str>(page(7))).unwrap();
        let second = cache.get_or_load(0, || Ok::<_, &str>(page(7))).unwrap();
        check!(Arc::ptr_eq(&first, &second));
    }

    /// The regression that a benchmark caught and review did not: an early
    /// gate released the lock before loading, so this counted N, not 1.
    #[test]
    fn concurrent_misses_on_one_page_load_once() {
        let cache = PageCache::new(Budget { pages: 4 });
        let calls = AtomicUsize::new(0);

        std::thread::scope(|s| {
            for _ in 0..16 {
                s.spawn(|| {
                    cache
                        .get_or_load(0, || {
                            calls.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            Ok::<_, &str>(page(3))
                        })
                        .unwrap()
                });
            }
        });

        check!(calls.load(Ordering::Relaxed) == 1);
    }

    #[test]
    fn distinct_pages_do_not_block_each_other() {
        let cache = PageCache::new(Budget { pages: 8 });
        let cache = &cache;
        let results: Vec<u8> = std::thread::scope(|s| {
            // Every thread must be spawned before any is joined, or they run
            // one at a time and the test stops proving anything.
            let mut handles = Vec::new();
            for i in 0..8u8 {
                handles.push(s.spawn(move || {
                    cache
                        .get_or_load(i as usize, || Ok::<_, &str>(page(i)))
                        .unwrap()[0]
                }));
            }
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        check!(results == (0..8).collect::<Vec<u8>>());
    }

    #[test]
    fn a_failed_load_is_not_cached() {
        let cache = PageCache::new(Budget { pages: 4 });
        check!(cache.get_or_load(0, || Err::<Vec<u8>, _>("boom")).is_err());
        check!(cache.get_or_load(0, || Ok::<_, &str>(page(9))).unwrap()[0] == 9);
    }

    #[test]
    fn eviction_keeps_the_cache_bounded() {
        let cache = PageCache::new(Budget { pages: 2 });
        for i in 0..8 {
            cache
                .get_or_load(i, || Ok::<_, &str>(page(i as u8)))
                .unwrap();
        }
        // The oldest entry is gone, so it reloads.
        let calls = AtomicUsize::new(0);
        cache
            .get_or_load(0, || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, &str>(page(0))
            })
            .unwrap();
        check!(calls.load(Ordering::Relaxed) == 1);
    }

    #[test]
    fn budget_adapts_to_page_size() {
        // Small pages: many fit, capped by how many the archive has.
        let small = Budget::from_pages(&[256 << 10; 600], 16);
        check!(small.pages > 8);

        // Large pages: the ceiling limits the count, but never below two.
        let large = Budget::from_pages(&[35 << 20; 35], 16);
        check!(large.pages >= 2);
        check!(large.pages < 35);
    }

    #[test]
    fn budget_handles_an_empty_page_table() {
        check!(Budget::from_pages(&[], 8).pages == 2);
    }
}
