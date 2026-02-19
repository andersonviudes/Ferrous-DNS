use compact_str::CompactString;
use rustc_hash::FxBuildHasher;
use smallvec::SmallVec;
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
        let labels: SmallVec<[&str; 8]> = domain.split('.').rev().collect();
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
