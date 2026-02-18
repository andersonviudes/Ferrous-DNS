use compact_str::CompactString;
use dashmap::DashMap;
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(60);
const L0_CAPACITY: usize = 256;

type BlockL0Cache = LruCache<(CompactString, i64), (bool, Instant), FxBuildHasher>;

// ---------------------------------------------------------------------------
// L0 — thread-local LRU (no lock, ~10ns hit)
// ---------------------------------------------------------------------------

thread_local! {
    static BLOCK_L0: RefCell<BlockL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(L0_CAPACITY).unwrap(),
            FxBuildHasher,
        ));
}

#[inline]
pub fn decision_l0_get(domain: &str, group_id: i64) -> Option<bool> {
    BLOCK_L0.with(|c| {
        let mut c = c.borrow_mut();
        let key = (CompactString::new(domain), group_id);
        if let Some((blocked, inserted_at)) = c.get(&key) {
            if inserted_at.elapsed() < TTL {
                return Some(*blocked);
            }
            c.pop(&key);
        }
        None
    })
}

#[inline]
pub fn decision_l0_set(domain: &str, group_id: i64, blocked: bool) {
    BLOCK_L0.with(|c| {
        c.borrow_mut().put(
            (CompactString::new(domain), group_id),
            (blocked, Instant::now()),
        );
    });
}

/// Drain the thread-local L0 cache. Called after a `BlockIndex` reload so that
/// stale decisions do not persist on the calling thread.
pub fn decision_l0_clear() {
    BLOCK_L0.with(|c| c.borrow_mut().clear());
}

// ---------------------------------------------------------------------------
// L1 — shared DashMap (TTL-gated, ~50ns hit)
// ---------------------------------------------------------------------------

/// Shared, multi-threaded Block Decision Cache.
///
/// Used as a secondary layer (L1) after the per-thread LRU (L0).
/// Entries expire after `TTL` (60 s). Cleared atomically after each reload
/// to prevent stale allow/block decisions from outliving an index swap.
pub struct BlockDecisionCache {
    inner: DashMap<(CompactString, i64), (bool, Instant), FxBuildHasher>,
}

impl BlockDecisionCache {
    pub fn new() -> Self {
        Self {
            inner: DashMap::with_hasher(FxBuildHasher),
        }
    }

    /// Returns the cached decision (true = blocked) for `(domain, group_id)`,
    /// or `None` if absent or expired.
    #[inline]
    pub fn get(&self, domain: &str, group_id: i64) -> Option<bool> {
        let key = (CompactString::new(domain), group_id);
        if let Some(entry) = self.inner.get(&key) {
            let (blocked, inserted_at) = *entry;
            if inserted_at.elapsed() < TTL {
                return Some(blocked);
            }
            // Entry expired — drop the ref before removing
            drop(entry);
            self.inner.remove(&key);
        }
        None
    }

    /// Store the decision for `(domain, group_id)`.
    #[inline]
    pub fn set(&self, domain: &str, group_id: i64, blocked: bool) {
        self.inner.insert(
            (CompactString::new(domain), group_id),
            (blocked, Instant::now()),
        );
    }

    /// Evict all cached decisions. Called after the `BlockIndex` is swapped so
    /// that freshly-compiled rules take effect immediately.
    pub fn clear(&self) {
        self.inner.clear();
    }
}

impl Default for BlockDecisionCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ---- L1 shared cache --------------------------------------------------

    #[test]
    fn test_l1_miss_on_empty() {
        let cache = BlockDecisionCache::new();
        assert_eq!(cache.get("ads.com", 1), None);
    }

    #[test]
    fn test_l1_stores_block_decision() {
        let cache = BlockDecisionCache::new();
        cache.set("ads.com", 1, true);
        assert_eq!(cache.get("ads.com", 1), Some(true));
    }

    #[test]
    fn test_l1_stores_allow_decision() {
        let cache = BlockDecisionCache::new();
        cache.set("safe.com", 1, false);
        assert_eq!(cache.get("safe.com", 1), Some(false));
    }

    #[test]
    fn test_l1_different_groups_independent() {
        let cache = BlockDecisionCache::new();
        cache.set("ads.com", 1, true);
        cache.set("ads.com", 2, false);
        assert_eq!(cache.get("ads.com", 1), Some(true));
        assert_eq!(cache.get("ads.com", 2), Some(false));
    }

    #[test]
    fn test_l1_clear_empties_cache() {
        let cache = BlockDecisionCache::new();
        cache.set("ads.com", 1, true);
        cache.set("tracker.io", 2, true);
        cache.clear();
        assert_eq!(cache.get("ads.com", 1), None);
        assert_eq!(cache.get("tracker.io", 2), None);
    }

    #[test]
    fn test_l1_overwrite_decision() {
        let cache = BlockDecisionCache::new();
        cache.set("ads.com", 1, true);
        cache.set("ads.com", 1, false); // flip to allow
        assert_eq!(cache.get("ads.com", 1), Some(false));
    }

    // ---- L0 thread-local cache --------------------------------------------

    #[test]
    fn test_l0_miss_on_empty() {
        // Each test runs in its own thread, L0 is always fresh.
        assert_eq!(decision_l0_get("ads.com", 1), None);
    }

    #[test]
    fn test_l0_stores_and_retrieves() {
        decision_l0_set("tracker.io", 1, true);
        assert_eq!(decision_l0_get("tracker.io", 1), Some(true));
        decision_l0_clear();
    }

    #[test]
    fn test_l0_different_threads_isolated() {
        // Set in this thread.
        decision_l0_set("ads.com", 1, true);

        // A new thread should see a miss (its own L0 is empty).
        let handle = thread::spawn(|| decision_l0_get("ads.com", 1));
        let result = handle.join().unwrap();
        assert_eq!(result, None);

        decision_l0_clear();
    }

    #[test]
    fn test_l0_clear_empties() {
        decision_l0_set("ads.com", 1, true);
        decision_l0_clear();
        assert_eq!(decision_l0_get("ads.com", 1), None);
    }
}
