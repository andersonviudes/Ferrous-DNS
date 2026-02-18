use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;
use std::sync::Arc;

/// One bit per blocklist source. Supports up to 63 external sources (bits 0-62)
/// plus bit 63 reserved for manual `blocklist` table entries.
pub type SourceBitSet = u64;

/// Bit 63 is reserved for entries coming from the manual `blocklist` table.
pub const MANUAL_SOURCE_BIT: u64 = 1u64 << 63;

/// Metadata about a single blocklist source (from `blocklist_sources` table).
#[derive(Debug, Clone)]
pub struct SourceMeta {
    pub id: i64,
    pub name: Arc<str>,
    pub group_id: i64,
    /// Bit position in SourceBitSet (0..62). Assigned at compile time.
    pub bit: u8,
}

/// Per-group and global allowlist.
///
/// Built from:
///   - `whitelist` table       → global_exact / global_wildcard (all groups)
///   - `whitelist_sources` rows → group_exact / group_wildcard (per group_id)
///
/// Immutable after construction (replaced wholesale via ArcSwap<BlockIndex>).
pub struct AllowlistIndex {
    pub global_exact: DashSet<CompactString, FxBuildHasher>,
    pub global_wildcard: SuffixTrie,
    pub group_exact: HashMap<i64, DashSet<CompactString, FxBuildHasher>>,
    pub group_wildcard: HashMap<i64, SuffixTrie>,
}

impl AllowlistIndex {
    pub fn new() -> Self {
        Self {
            global_exact: DashSet::with_hasher(FxBuildHasher),
            global_wildcard: SuffixTrie::new(),
            group_exact: HashMap::new(),
            group_wildcard: HashMap::new(),
        }
    }

    /// Returns true if `domain` is allowlisted for `group_id`.
    ///
    /// Check order:
    ///   1. Group-specific exact
    ///   2. Group-specific wildcard
    ///   3. Global exact
    ///   4. Global wildcard
    #[inline]
    pub fn is_allowed(&self, domain: &str, group_id: i64) -> bool {
        if let Some(set) = self.group_exact.get(&group_id) {
            if set.contains(domain) {
                return true;
            }
        }
        if let Some(trie) = self.group_wildcard.get(&group_id) {
            if trie.lookup(domain) != 0 {
                return true;
            }
        }
        if self.global_exact.contains(domain) {
            return true;
        }
        if self.global_wildcard.lookup(domain) != 0 {
            return true;
        }
        false
    }
}

impl Default for AllowlistIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// The compiled block filter index. Immutable once built.
///
/// Replaced atomically via `ArcSwap<BlockIndex>` during reload — zero downtime.
pub struct BlockIndex {
    /// Source metadata (index == bit position in SourceBitSet).
    pub sources: Vec<SourceMeta>,

    /// group_id → active SourceBitSet mask.
    ///
    /// Non-default groups inherit the default group's bits plus their own:
    ///   group 2 mask = default_mask | bit(source_2)
    pub group_masks: HashMap<i64, SourceBitSet>,

    pub default_group_id: i64,

    /// L3: Exact domain lookup. Key is lowercase domain.
    /// Value = SourceBitSet (which sources block this exact domain).
    pub exact: DashMap<CompactString, SourceBitSet, FxBuildHasher>,

    /// L2: Bloom filter over all exact-blocked domains.
    /// False-positive rate ~0.1%. Bloom miss guarantees absence from `exact`.
    pub bloom: AtomicBloom,

    /// L4: Wildcard suffix trie (*.pattern).
    pub wildcard: SuffixTrie,

    /// L5: Aho-Corasick substring patterns.
    /// Tuple: (compiled automaton, SourceBitSet of sources that contributed patterns).
    pub patterns: Vec<(AhoCorasick, SourceBitSet)>,

    /// Allowlist overrides (checked before the block pipeline).
    pub allowlists: AllowlistIndex,
}

impl BlockIndex {
    /// Returns the SourceBitSet mask for `group_id`, falling back to the default
    /// group mask if `group_id` is not found.
    #[inline]
    pub fn group_mask(&self, group_id: i64) -> SourceBitSet {
        self.group_masks
            .get(&group_id)
            .copied()
            .unwrap_or_else(|| {
                self.group_masks
                    .get(&self.default_group_id)
                    .copied()
                    .unwrap_or(u64::MAX)
            })
    }

    /// Core lookup: returns true if `domain` is blocked for `group_id`.
    ///
    /// Pipeline (fast-path first):
    ///   AllowlistIndex   → early Allow if domain is whitelisted
    ///   Bloom filter     → if miss, skip exact DashMap lookup
    ///   Exact DashMap    → bits & group_mask ≠ 0 → Block
    ///   SuffixTrie       → wildcard match + bitcheck → Block
    ///   Aho-Corasick     → pattern match + bitcheck → Block
    #[inline]
    pub fn is_blocked(&self, domain: &str, group_id: i64) -> bool {
        // L0+L1: Allowlist override — highest priority, always checked first
        if self.allowlists.is_allowed(domain, group_id) {
            return false;
        }

        let mask = self.group_mask(group_id);

        // L2: Bloom filter — gates the exact DashMap lookup only.
        // Wildcard and pattern checks happen regardless of bloom result because
        // the bloom only covers exact domains, not wildcard/pattern entries.
        let bloom_hit = self.bloom.check(&domain);

        if bloom_hit {
            // L3: Exact match
            if let Some(entry) = self.exact.get(domain) {
                if entry.value() & mask != 0 {
                    return true;
                }
            }
        }

        // L4: Wildcard suffix trie
        // L5: Aho-Corasick patterns
        self.check_wildcard_and_patterns(domain, mask)
    }

    #[inline]
    fn check_wildcard_and_patterns(&self, domain: &str, mask: SourceBitSet) -> bool {
        let wildcard_bits = self.wildcard.lookup(domain);
        if wildcard_bits & mask != 0 {
            return true;
        }

        for (ac, source_mask) in &self.patterns {
            if source_mask & mask != 0 && ac.is_match(domain) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal BlockIndex for testing without HTTP or DB.
    fn build_test_index(
        group_masks: HashMap<i64, SourceBitSet>,
        exact_entries: Vec<(&str, SourceBitSet)>,
        default_group_id: i64,
    ) -> BlockIndex {
        let bloom_capacity = (exact_entries.len() + 100).max(1000);
        let bloom = AtomicBloom::new(bloom_capacity, 0.001);

        let exact: DashMap<CompactString, SourceBitSet, FxBuildHasher> =
            DashMap::with_hasher(FxBuildHasher);

        for (domain, bits) in &exact_entries {
            bloom.set(domain);
            exact.insert(CompactString::new(domain), *bits);
        }

        BlockIndex {
            sources: vec![],
            group_masks,
            default_group_id,
            exact,
            bloom,
            wildcard: SuffixTrie::new(),
            patterns: vec![],
            allowlists: AllowlistIndex::new(),
        }
    }

    #[test]
    fn test_exact_match_blocked_correct_group() {
        // Source at bit 0 belongs to group 1
        let mut masks = HashMap::new();
        masks.insert(1i64, 0b01u64);

        let index = build_test_index(masks, vec![("ads.com", 0b01)], 1);
        assert!(index.is_blocked("ads.com", 1));
    }

    #[test]
    fn test_exact_match_wrong_group() {
        // Source bit 0 is in group 1. Group 2 mask does NOT include bit 0.
        let mut masks = HashMap::new();
        masks.insert(1i64, 0b01u64);
        masks.insert(2i64, 0b10u64); // bit 1 only

        let index = build_test_index(masks, vec![("ads.com", 0b01)], 1);
        // group 2 has mask 0b10, domain has bits 0b01 → AND = 0 → Allow
        assert!(!index.is_blocked("ads.com", 2));
    }

    #[test]
    fn test_allowlist_overrides_blocklist() {
        let mut masks = HashMap::new();
        masks.insert(1i64, 0b01u64);

        let bloom = AtomicBloom::new(1000, 0.001);
        bloom.set(&"ads.com");
        let exact: DashMap<CompactString, SourceBitSet, FxBuildHasher> =
            DashMap::with_hasher(FxBuildHasher);
        exact.insert(CompactString::new("ads.com"), 0b01);

        let mut allowlists = AllowlistIndex::new();
        allowlists.global_exact.insert(CompactString::new("ads.com"));

        let index = BlockIndex {
            sources: vec![],
            group_masks: masks,
            default_group_id: 1,
            exact,
            bloom,
            wildcard: SuffixTrie::new(),
            patterns: vec![],
            allowlists,
        };

        // Even though ads.com is blocked, the global allowlist overrides it
        assert!(!index.is_blocked("ads.com", 1));
    }

    #[test]
    fn test_wildcard_blocked_via_trie() {
        let mut masks = HashMap::new();
        masks.insert(1i64, 0b01u64);

        let bloom = AtomicBloom::new(1000, 0.001);
        let exact: DashMap<CompactString, SourceBitSet, FxBuildHasher> =
            DashMap::with_hasher(FxBuildHasher);

        let mut wildcard = SuffixTrie::new();
        wildcard.insert_wildcard("*.tracker.io", 0b01);

        let index = BlockIndex {
            sources: vec![],
            group_masks: masks,
            default_group_id: 1,
            exact,
            bloom,
            wildcard,
            patterns: vec![],
            allowlists: AllowlistIndex::new(),
        };

        assert!(index.is_blocked("evil.tracker.io", 1));
        assert!(!index.is_blocked("safe.com", 1));
    }

    #[test]
    fn test_default_group_fallback_mask() {
        let mut masks = HashMap::new();
        masks.insert(1i64, 0b01u64); // only default group defined

        let index = build_test_index(masks, vec![("ads.com", 0b01)], 1);
        // group 99 is unknown → falls back to default group mask (0b01)
        assert!(index.is_blocked("ads.com", 99));
    }

    #[test]
    fn test_group_mask_inheritance() {
        // Default group = 1, bits 0+1. Kids group = 2, default bits + bit 2.
        let mut masks = HashMap::new();
        masks.insert(1i64, 0b011u64); // bits 0,1
        masks.insert(2i64, 0b111u64); // bits 0,1,2

        let index = build_test_index(masks, vec![("kids-only-blocked.com", 0b100)], 1);

        // Default group doesn't have bit 2 → not blocked
        assert!(!index.is_blocked("kids-only-blocked.com", 1));
        // Kids group has bit 2 → blocked
        assert!(index.is_blocked("kids-only-blocked.com", 2));
    }
}
