use crate::dns::cache::coarse_clock::coarse_now_secs;
use dashmap::DashMap;
use ferrous_dns_domain::BlockSource;
use lru::LruCache;
use rustc_hash::{FxBuildHasher, FxHasher};
use std::cell::RefCell;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

const TTL_SECS: u64 = 60;
const L0_CAPACITY: usize = 256;
const L1_CAPACITY: usize = 100_000;

/// Cache encoding: 0 = allow, 1 = Blocklist, 2 = ManagedDomain, 3 = RegexFilter
const CACHE_ALLOW: u8 = 0;

fn encode_source(source: Option<BlockSource>) -> u8 {
    match source {
        None => CACHE_ALLOW,
        Some(s) => s.as_u8() + 1,
    }
}

fn decode_source(val: u8) -> Option<BlockSource> {
    if val == CACHE_ALLOW {
        None
    } else {
        BlockSource::from_u8(val - 1)
    }
}

fn decision_key(domain: &str, group_id: i64) -> u64 {
    let mut h = FxHasher::default();
    domain.hash(&mut h);
    group_id.hash(&mut h);
    h.finish()
}

// (encoded_source, timestamp)
type BlockL0Cache = LruCache<u64, (u8, u64), FxBuildHasher>;

thread_local! {
    static BLOCK_L0: RefCell<BlockL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(L0_CAPACITY).unwrap(),
            FxBuildHasher,
        ));
}

/// Returns `None` on cache miss, `Some(None)` for cached allow, `Some(Some(source))` for cached block.
#[inline]
pub fn decision_l0_get(domain: &str, group_id: i64) -> Option<Option<BlockSource>> {
    BLOCK_L0.with(|c| {
        let mut c = c.borrow_mut();
        let key = decision_key(domain, group_id);
        if let Some(&(encoded, inserted_at)) = c.get(&key) {
            if coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS {
                return Some(decode_source(encoded));
            }
            c.pop(&key);
        }
        None
    })
}

#[inline]
pub fn decision_l0_set(domain: &str, group_id: i64, source: Option<BlockSource>) {
    BLOCK_L0.with(|c| {
        c.borrow_mut().put(
            decision_key(domain, group_id),
            (encode_source(source), coarse_now_secs()),
        );
    });
}

pub fn decision_l0_clear() {
    BLOCK_L0.with(|c| c.borrow_mut().clear());
}

/// Shared L1 block-decision cache backed by a lock-free `DashMap`.
///
/// Replaces the previous `Mutex<LruCache>` design.  Since every entry carries
/// a TTL timestamp, strict LRU ordering is not required for correctness: stale
/// entries are rejected on read and overwritten on the next write.  The
/// `DashMap` lets multiple tokio worker threads read and write concurrently
/// without serialising through a single global mutex.
///
/// When the map exceeds `L1_CAPACITY` entries, new inserts are dropped to
/// bound memory.  The TTL (60 s) ensures natural turnover so the map does not
/// fill with stale data under normal load.
pub struct BlockDecisionCache {
    inner: DashMap<u64, (u8, u64), FxBuildHasher>,
    len: AtomicUsize,
}

impl BlockDecisionCache {
    pub fn new() -> Self {
        Self {
            inner: DashMap::with_capacity_and_hasher(L1_CAPACITY, FxBuildHasher),
            len: AtomicUsize::new(0),
        }
    }

    /// Returns `None` on cache miss, `Some(None)` for cached allow, `Some(Some(source))` for cached block.
    #[inline]
    pub fn get(&self, domain: &str, group_id: i64) -> Option<Option<BlockSource>> {
        let key = decision_key(domain, group_id);
        if let Some(entry) = self.inner.get(&key) {
            let (encoded, inserted_at) = *entry;
            if coarse_now_secs().saturating_sub(inserted_at) < TTL_SECS {
                return Some(decode_source(encoded));
            }
            // Entry is stale — drop the shared ref before removing.
            drop(entry);
            self.inner.remove(&key);
            self.len.fetch_sub(1, AtomicOrdering::Relaxed);
        }
        None
    }

    #[inline]
    pub fn set(&self, domain: &str, group_id: i64, source: Option<BlockSource>) {
        // Bound memory: skip insert when the cache is at capacity.
        // Stale entries will be evicted organically by `get()` reads or
        // by the next `clear()` call on blocklist reload.
        if self.len.load(AtomicOrdering::Relaxed) >= L1_CAPACITY {
            return;
        }
        let key = decision_key(domain, group_id);
        let is_new = !self.inner.contains_key(&key);
        self.inner.insert(key, (encode_source(source), coarse_now_secs()));
        if is_new {
            self.len.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    pub fn clear(&self) {
        self.inner.clear();
        self.len.store(0, AtomicOrdering::Relaxed);
    }
}

impl Default for BlockDecisionCache {
    fn default() -> Self {
        Self::new()
    }
}
