use compact_str::CompactString;
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;

/// A node in the reversed-label suffix trie.
#[derive(Default)]
struct TrieNode {
    children: HashMap<CompactString, TrieNode, FxBuildHasher>,
    /// SourceBitSet for wildcard patterns terminating at this node.
    /// `*.ads.com` sets wildcard_mask at the "ads" node after traversing "com".
    wildcard_mask: u64,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::with_hasher(FxBuildHasher),
            wildcard_mask: 0,
        }
    }
}

/// Suffix trie for wildcard domain matching.
///
/// Patterns like `*.ads.com` are stored as reversed label paths.
/// `*.ads.com` → traverse ["com", "ads"], set wildcard_mask at "ads" node.
///
/// Lookup for `sub.ads.com`:
///   Reversed labels: ["com", "ads", "sub"]
///   Walk: root → "com" → "ads" (wildcard_mask set → match!)
///
/// This struct is built once during compilation and replaced via ArcSwap.
#[derive(Default)]
pub struct SuffixTrie {
    root: TrieNode,
}

impl SuffixTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
        }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty()
    }

    /// Insert a wildcard pattern like `*.ads.com` with its source bitmask.
    ///
    /// The leading `*.` is stripped before traversal.
    /// If the same node is matched by multiple sources, their bits are OR-merged.
    pub fn insert_wildcard(&mut self, pattern: &str, source_mask: u64) {
        let domain = pattern.strip_prefix("*.").unwrap_or(pattern);
        let mut node = &mut self.root;
        // Traverse labels in reverse order (com → ads → ...)
        for label in domain.split('.').rev() {
            node = node.children.entry(CompactString::new(label)).or_default();
        }
        node.wildcard_mask |= source_mask;
    }

    /// Look up `domain` and return the combined SourceBitSet of all matching
    /// wildcard patterns, or 0 if there is no match.
    ///
    /// A `wildcard_mask` at node N means any domain that passes through N **and
    /// has at least one more label** (subdomain) is matched.  The parent domain
    /// itself does NOT match: `*.ads.com` matches `sub.ads.com` but NOT `ads.com`.
    #[inline]
    pub fn lookup(&self, domain: &str) -> u64 {
        let labels: Vec<&str> = domain.split('.').rev().collect();
        let n = labels.len();
        let mut node = &self.root;
        let mut result: u64 = 0;

        for (i, label) in labels.iter().enumerate() {
            match node.children.get(*label) {
                Some(child) => {
                    // Wildcard match requires at least one subdomain label beyond
                    // the node (i.e. at least one label still remaining after this one).
                    if child.wildcard_mask != 0 && i + 1 < n {
                        result |= child.wildcard_mask;
                        // Keep walking: deeper patterns (*.sub.ads.com) may add more bits
                    }
                    node = child;
                }
                None => break,
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matches_subdomain() {
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("*.ads.com", 0b01);
        assert_eq!(trie.lookup("sub.ads.com"), 0b01);
        assert_eq!(trie.lookup("deep.sub.ads.com"), 0b01);
    }

    #[test]
    fn test_wildcard_no_match_parent_domain() {
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("*.ads.com", 0b01);
        // The parent itself is not matched by a wildcard — use exact map for that
        assert_eq!(trie.lookup("ads.com"), 0);
    }

    #[test]
    fn test_wildcard_no_match_unrelated() {
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("*.ads.com", 0b01);
        assert_eq!(trie.lookup("safe.com"), 0);
        assert_eq!(trie.lookup("notads.com"), 0);
    }

    #[test]
    fn test_nested_wildcard() {
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("*.sub.ads.com", 0b01);
        assert_eq!(trie.lookup("deep.sub.ads.com"), 0b01);
        // *.sub.ads.com should NOT match sub.ads.com directly
        assert_eq!(trie.lookup("sub.ads.com"), 0);
    }

    #[test]
    fn test_multiple_sources_or_mask() {
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("*.ads.com", 0b01);
        trie.insert_wildcard("*.ads.com", 0b10);
        assert_eq!(trie.lookup("x.ads.com"), 0b11);
    }

    #[test]
    fn test_overlapping_patterns() {
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("*.ads.com", 0b01);
        trie.insert_wildcard("*.sub.ads.com", 0b10);
        // deep.sub.ads.com matches both
        assert_eq!(trie.lookup("deep.sub.ads.com"), 0b11);
        // x.ads.com only matches the first
        assert_eq!(trie.lookup("x.ads.com"), 0b01);
    }

    #[test]
    fn test_empty_trie_returns_zero() {
        let trie = SuffixTrie::new();
        assert_eq!(trie.lookup("anything.com"), 0);
        assert!(trie.is_empty());
    }

    #[test]
    fn test_insert_without_wildcard_prefix() {
        // insert_wildcard with no leading "*." still works (treated as suffix of parent)
        let mut trie = SuffixTrie::new();
        trie.insert_wildcard("ads.com", 0b01);
        // anything under ads.com matches
        assert_eq!(trie.lookup("sub.ads.com"), 0b01);
    }
}
