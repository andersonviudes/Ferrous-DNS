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
    #[allow(dead_code)]
    pub id: i64,
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    pub sources: Vec<SourceMeta>,

    /// group_id → active SourceBitSet mask.
    ///
    /// Non-default groups inherit the default group's bits plus their own:
    ///   group 2 mask = default_mask | bit(source_2)
    pub group_masks: HashMap<i64, SourceBitSet>,

    pub default_group_id: i64,

    /// Total number of unique exact-blocked domains in this index.
    pub total_blocked_domains: usize,

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
        self.group_masks.get(&group_id).copied().unwrap_or_else(|| {
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
