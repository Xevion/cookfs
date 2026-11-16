//! Bounded page cache.
//!
//! Pages are handed out as `Arc<Vec<u8>>` so a hit never copies. The policy is LRU
//! with a per-page load gate, chosen from measurements over a corpus of real
//! installers rather than from first principles.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use lru::LruCache;
use parking_lot::Mutex;

/// A decompressed page, shared by every reader that asked for it.
///
/// A `Vec` rather than `[u8]` behind the `Arc`, since converting a decoded
/// `Vec` into `Arc<[u8]>` copies the whole page into a new allocation.
pub(crate) type Page = Arc<Vec<u8>>;

/// How many decoded bytes the cache may retain, derived from an archive's own page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budget {
    /// Resident decoded bytes, past which the least recent pages are dropped.
    pub(crate) bytes: usize,
}

impl Budget {
    /// Cache floor and ceiling in bytes.
    ///
    /// A library should not claim hundreds of megabytes without being asked, so
    /// the ceiling is deliberately modest; sequential reads stay optimal well
    /// below it because LRU only needs the page currently being consumed.
    const FLOOR: u64 = 8 << 20;
    const CEILING: u64 = 128 << 20;

    /// Sizes the cache from the page sizes the page table declares before any page is read.
    ///
    /// Page sizes span two orders of magnitude across real archives (hundreds
    /// of KB in IDA installers, tens of MB in Bitnami stacks), so any fixed
    /// value either thrashes on one shape or wastes memory on the other.
    /// Holding a couple of pages per worker lets each thread own one and still
    /// reuse a neighbour's. The sizes only steer the budget; eviction counts
    /// the bytes each page really decoded to, so a lying table cannot inflate it.
    pub(crate) fn from_pages(declared: &[u32], workers: usize) -> Self {
        let count = declared.len().max(1);
        let mean = declared.iter().map(|&s| u64::from(s)).sum::<u64>() / count as u64;
        let want = (2 * workers as u64 * mean).clamp(Self::FLOOR, Self::CEILING);
        Self {
            bytes: usize::try_from(want).unwrap_or(usize::MAX),
        }
    }
}

/// One cached page and the decoded bytes it was counted at, both guarded by the cache.
#[derive(Debug, Default)]
struct Slot {
    page: Mutex<Option<Page>>,
    /// Bytes this slot adds to the cache's total; only touched under the outer lock.
    counted: AtomicUsize,
}

#[derive(Debug)]
struct Slots {
    lru: LruCache<usize, Arc<Slot>>,
    bytes: usize,
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
pub(crate) struct PageCache {
    slots: Mutex<Slots>,
    budget: usize,
}

impl PageCache {
    /// Builds a cache holding at most `budget.bytes` of decoded pages, beyond the one most recently loaded.
    pub(crate) fn new(budget: Budget) -> Self {
        Self {
            slots: Mutex::new(Slots {
                lru: LruCache::unbounded(),
                bytes: 0,
            }),
            budget: budget.bytes,
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
    pub(crate) fn get_or_load<E>(
        &self,
        n: usize,
        load: impl FnOnce() -> Result<Vec<u8>, E>,
    ) -> Result<Page, E> {
        let slot = self
            .slots
            .lock()
            .lru
            .get_or_insert(n, || Arc::new(Slot::default()))
            .clone();

        let mut guard = slot.page.lock();
        if let Some(hit) = guard.as_ref() {
            return Ok(hit.clone());
        }
        let mut decoded = load()?;
        // A decoder reserves ahead of what it proves it needs; a cached page keeps only its bytes.
        decoded.shrink_to_fit();
        let page: Page = Arc::new(decoded);
        *guard = Some(page.clone());
        drop(guard);
        self.admit(n, &slot, page.len());
        Ok(page)
    }

    /// Counts a freshly loaded page, then drops the least recent others until the total fits.
    fn admit(&self, n: usize, slot: &Arc<Slot>, len: usize) {
        let mut slots = self.slots.lock();
        // A slot evicted while it loaded is no longer the cache's to count.
        if !slots.lru.peek(&n).is_some_and(|s| Arc::ptr_eq(s, slot)) {
            return;
        }
        slot.counted.store(len, Ordering::Relaxed);
        slots.bytes += len;
        // The newest page stays even alone over budget, rather than never being cached.
        slots.lru.promote(&n);
        while slots.bytes > self.budget && slots.lru.len() > 1 {
            let Some((_, oldest)) = slots.lru.pop_lru() else {
                break;
            };
            slots.bytes -= oldest.counted.load(Ordering::Relaxed);
        }
        drop(slots);
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
        let cache = PageCache::new(Budget { bytes: 1 << 20 });
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
        let cache = PageCache::new(Budget { bytes: 1 << 20 });
        let first = cache.get_or_load(0, || Ok::<_, &str>(page(7))).unwrap();
        let second = cache.get_or_load(0, || Ok::<_, &str>(page(7))).unwrap();
        check!(Arc::ptr_eq(&first, &second));
    }

    /// The regression that a benchmark caught and review did not: an early
    /// gate released the lock before loading, so this counted N, not 1.
    #[test]
    fn concurrent_misses_on_one_page_load_once() {
        let cache = PageCache::new(Budget { bytes: 1 << 20 });
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
        let cache = PageCache::new(Budget { bytes: 1 << 20 });
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
        let cache = PageCache::new(Budget { bytes: 1 << 20 });
        check!(cache.get_or_load(0, || Err::<Vec<u8>, _>("boom")).is_err());
        check!(cache.get_or_load(0, || Ok::<_, &str>(page(9))).unwrap()[0] == 9);
    }

    #[test]
    fn eviction_keeps_the_cache_bounded() {
        let cache = PageCache::new(Budget { bytes: 16 });
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

    /// Pages that decode far larger than the table declares are still evicted by what they hold.
    #[test]
    fn eviction_counts_decoded_bytes_not_entries() {
        let budget = Budget::from_pages(&[1; 64], 4);
        let cache = PageCache::new(budget);
        for i in 0..64 {
            cache
                .get_or_load(i, || Ok::<_, &str>(vec![0; 1 << 20]))
                .unwrap();
        }
        let (bytes, held) = {
            let slots = cache.slots.lock();
            (slots.bytes, slots.lru.len())
        };
        check!(bytes <= budget.bytes);
        check!(held == budget.bytes >> 20);
    }

    #[test]
    fn a_page_larger_than_the_budget_is_still_kept_alone() {
        let cache = PageCache::new(Budget { bytes: 4 });
        cache.get_or_load(0, || Ok::<_, &str>(page(1))).unwrap();
        cache.get_or_load(1, || Ok::<_, &str>(page(2))).unwrap();
        let (held, newest) = {
            let slots = cache.slots.lock();
            (slots.lru.len(), slots.lru.peek(&1).is_some())
        };
        check!(held == 1);
        check!(newest);
    }

    #[test]
    fn the_budget_stays_between_its_floor_and_ceiling() {
        check!(Budget::from_pages(&[], 8).bytes == Budget::FLOOR as usize);
        check!(Budget::from_pages(&[u32::MAX; 4], 64).bytes == Budget::CEILING as usize);
    }
}
