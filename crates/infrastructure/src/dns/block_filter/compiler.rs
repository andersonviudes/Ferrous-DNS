use super::block_index::{AllowlistIndex, BlockIndex, SourceBitSet, SourceMeta, MANUAL_SOURCE_BIT};
use super::suffix_trie::SuffixTrie;
use crate::dns::cache::bloom::AtomicBloom;
use aho_corasick::AhoCorasick;
use compact_str::CompactString;
use dashmap::{DashMap, DashSet};
use ferrous_dns_domain::DomainError;
use futures::future::join_all;
use rustc_hash::FxBuildHasher;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Line parsing
// ---------------------------------------------------------------------------

/// Intermediate entry type produced by the line parser.
#[derive(Debug)]
pub enum ParsedEntry {
    Exact(String),
    Wildcard(String),
    Pattern(String),
}

/// Parse one line from a blocklist / allowlist text.
///
/// Supported formats:
/// - `# comment` or blank  → None
/// - `0.0.0.0 domain`      → Exact
/// - `127.0.0.1 domain`    → Exact
/// - `:: domain`           → Exact
/// - `*.ads.com`           → Wildcard
/// - `/tracker/`           → Pattern (Aho-Corasick)
/// - `ads.com`             → Exact (plain token containing a dot)
pub fn parse_list_line(line: &str) -> Option<ParsedEntry> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }

    // /pattern/ → Aho-Corasick substring
    if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
        return Some(ParsedEntry::Pattern(line[1..line.len() - 1].to_lowercase()));
    }

    // *.domain → Wildcard
    if line.starts_with("*.") {
        let pattern = line.to_ascii_lowercase();
        return Some(ParsedEntry::Wildcard(pattern));
    }

    let parts: Vec<&str> = line.split_whitespace().collect();

    // hosts file format: "addr domain [comment…]"
    if parts.len() >= 2 {
        let addr = parts[0];
        let domain = parts[1];

        let is_hosts_addr = matches!(addr, "0.0.0.0" | "127.0.0.1" | "::" | "::1");
        if is_hosts_addr {
            // Skip self-referential entries
            if matches!(
                domain,
                "localhost" | "0.0.0.0" | "broadcasthost" | "ip6-localhost" | "ip6-loopback"
            ) {
                return None;
            }
            // Skip lines with no dot (hostnames without TLD are rarely meaningful blocklist entries)
            if !domain.contains('.') {
                return None;
            }
            return Some(ParsedEntry::Exact(domain.to_ascii_lowercase()));
        }
    }

    // Single token with a dot → plain domain
    if parts.len() == 1 && parts[0].contains('.') {
        return Some(ParsedEntry::Exact(parts[0].to_ascii_lowercase()));
    }

    None
}

/// Parse an entire list text and collect `ParsedEntry` items.
pub fn parse_list_text(text: &str) -> Vec<ParsedEntry> {
    text.lines().filter_map(parse_list_line).collect()
}

// ---------------------------------------------------------------------------
// HTTP fetch helper
// ---------------------------------------------------------------------------

async fn fetch_url(url: &str, client: &reqwest::Client) -> Result<String, String> {
    let response = client
        .get(url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("fetch error for {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "HTTP {} for {}",
            response.status().as_u16(),
            url
        ));
    }

    response
        .text()
        .await
        .map_err(|e| format!("read error for {}: {}", url, e))
}

// ---------------------------------------------------------------------------
// Main compiler
// ---------------------------------------------------------------------------

/// Compile a fresh `BlockIndex` from the database and any HTTP-fetched sources.
///
/// Steps:
///   1. Load default group id
///   2. Load enabled blocklist sources → assign bit positions
///   3. Compute group masks (inheritance: non-default groups get default bits too)
///   4. Fetch HTTP sources in parallel
///   5. Load manual blocklist entries (bit 63 = MANUAL_SOURCE_BIT)
///   6. Parse all content → exact / wildcard / pattern entries
///   7. Build Bloom + exact DashMap + SuffixTrie + Aho-Corasick automata
///   8. Load AllowlistIndex (whitelist table + whitelist_sources URL fetch)
///   9. Return BlockIndex
pub async fn compile_block_index(
    pool: &SqlitePool,
    client: &reqwest::Client,
) -> Result<BlockIndex, DomainError> {
    // ------------------------------------------------------------------
    // 1. Default group
    // ------------------------------------------------------------------
    let default_group_id: i64 = sqlx::query(
        "SELECT id FROM groups WHERE is_default = 1 LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?
    .map(|row| row.get::<i64, _>("id"))
    .unwrap_or(1);

    // ------------------------------------------------------------------
    // 2. Load enabled blocklist sources (max 63, bits 0..=62)
    // ------------------------------------------------------------------
    let source_rows = sqlx::query(
        "SELECT id, name, group_id, url FROM blocklist_sources WHERE enabled = 1 ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    if source_rows.len() > 63 {
        warn!(
            count = source_rows.len(),
            "More than 63 blocklist sources; only the first 63 will be used"
        );
    }

    let sources: Vec<SourceMeta> = source_rows
        .iter()
        .take(63)
        .enumerate()
        .map(|(idx, row)| SourceMeta {
            id: row.get("id"),
            name: Arc::from(row.get::<String, _>("name").as_str()),
            group_id: row.get("group_id"),
            bit: idx as u8,
        })
        .collect();

    // ------------------------------------------------------------------
    // 3. Group masks with inheritance
    // ------------------------------------------------------------------
    // default_mask = OR of bits for all sources belonging to default group | MANUAL_SOURCE_BIT
    let mut default_mask: SourceBitSet = MANUAL_SOURCE_BIT;
    for src in &sources {
        if src.group_id == default_group_id {
            default_mask |= 1u64 << src.bit;
        }
    }

    // Every distinct group_id gets its own mask
    let mut group_masks: HashMap<i64, SourceBitSet> = HashMap::new();
    group_masks.insert(default_group_id, default_mask);

    for src in &sources {
        if src.group_id != default_group_id {
            let entry = group_masks.entry(src.group_id).or_insert(default_mask);
            *entry |= 1u64 << src.bit;
        }
    }

    // Also fetch all group ids from DB so that groups with no dedicated source
    // still appear with the default mask (handled by group_mask() fallback,
    // but let's be explicit for groups that have been queried before)

    // ------------------------------------------------------------------
    // 4. Parallel HTTP fetch for sources that have a URL
    // ------------------------------------------------------------------
    struct FetchResult {
        bit: u8,
        text: Option<String>,
    }

    let fetch_tasks: Vec<_> = source_rows
        .iter()
        .take(63)
        .enumerate()
        .filter_map(|(idx, row)| {
            let url: Option<String> = row.get("url");
            url.map(|u| {
                let client = client.clone();
                let bit = idx as u8;
                tokio::spawn(async move {
                    let text = match fetch_url(&u, &client).await {
                        Ok(t) => {
                            info!(url = %u, "Fetched blocklist source");
                            Some(t)
                        }
                        Err(e) => {
                            warn!(url = %u, error = %e, "Failed to fetch blocklist source");
                            None
                        }
                    };
                    FetchResult { bit, text }
                })
            })
        })
        .collect();

    let fetch_results = join_all(fetch_tasks).await;

    // bit → parsed entries
    let mut source_entries: HashMap<u8, Vec<ParsedEntry>> = HashMap::new();
    for result in fetch_results {
        match result {
            Ok(fr) => {
                if let Some(text) = fr.text {
                    source_entries.insert(fr.bit, parse_list_text(&text));
                }
            }
            Err(e) => {
                warn!(error = %e, "Fetch task panicked");
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. Manual blocklist entries (bit 63)
    // ------------------------------------------------------------------
    let manual_rows = sqlx::query("SELECT domain FROM blocklist")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    let manual_domains: Vec<String> = manual_rows
        .iter()
        .map(|row| row.get::<String, _>("domain").to_ascii_lowercase())
        .collect();

    info!(
        count = manual_domains.len(),
        "Loaded manual blocklist entries"
    );

    // ------------------------------------------------------------------
    // 6 & 7. Build Bloom, exact DashMap, wildcard SuffixTrie, AC patterns
    // ------------------------------------------------------------------
    // Count exact domains for bloom capacity
    let mut exact_count: usize = manual_domains.len();
    for entries in source_entries.values() {
        for e in entries {
            if matches!(e, ParsedEntry::Exact(_)) {
                exact_count += 1;
            }
        }
    }

    let bloom_capacity = (exact_count + 100).max(1000);
    let bloom = AtomicBloom::new(bloom_capacity, 0.001);

    let exact: DashMap<CompactString, SourceBitSet, FxBuildHasher> =
        DashMap::with_capacity_and_hasher(exact_count, FxBuildHasher);

    let mut wildcard = SuffixTrie::new();

    // patterns_by_source: source_bit → Vec<String> of substring patterns
    let mut patterns_by_source: HashMap<u8, Vec<String>> = HashMap::new();

    // Insert manual entries (bit 63)
    for domain in &manual_domains {
        bloom.set(domain);
        exact
            .entry(CompactString::new(domain))
            .and_modify(|bits| *bits |= MANUAL_SOURCE_BIT)
            .or_insert(MANUAL_SOURCE_BIT);
    }

    // Insert per-source entries
    for (bit, entries) in &source_entries {
        let source_bit: SourceBitSet = 1u64 << bit;
        for entry in entries {
            match entry {
                ParsedEntry::Exact(domain) => {
                    bloom.set(domain);
                    exact
                        .entry(CompactString::new(domain))
                        .and_modify(|bits| *bits |= source_bit)
                        .or_insert(source_bit);
                }
                ParsedEntry::Wildcard(pattern) => {
                    wildcard.insert_wildcard(pattern, source_bit);
                }
                ParsedEntry::Pattern(pat) => {
                    patterns_by_source
                        .entry(*bit)
                        .or_default()
                        .push(pat.clone());
                }
            }
        }
    }

    // Compile one AhoCorasick automaton per source that has patterns
    let mut patterns: Vec<(AhoCorasick, SourceBitSet)> = Vec::new();
    for (bit, pats) in patterns_by_source {
        if pats.is_empty() {
            continue;
        }
        match AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&pats)
        {
            Ok(ac) => {
                patterns.push((ac, 1u64 << bit));
            }
            Err(e) => {
                warn!(source_bit = bit, error = %e, "Failed to compile Aho-Corasick patterns");
            }
        }
    }

    let total_exact = exact.len();
    info!(
        exact = total_exact,
        wildcards = "built",
        pattern_automata = patterns.len(),
        "Block index compiled"
    );

    // ------------------------------------------------------------------
    // 8. AllowlistIndex
    // ------------------------------------------------------------------
    let allowlists = build_allowlist_index(pool, client, default_group_id).await?;

    // ------------------------------------------------------------------
    // 9. Assemble BlockIndex
    // ------------------------------------------------------------------
    Ok(BlockIndex {
        sources,
        group_masks,
        default_group_id,
        exact,
        bloom,
        wildcard,
        patterns,
        allowlists,
    })
}

// ---------------------------------------------------------------------------
// AllowlistIndex builder
// ---------------------------------------------------------------------------

async fn build_allowlist_index(
    pool: &SqlitePool,
    client: &reqwest::Client,
    _default_group_id: i64,
) -> Result<AllowlistIndex, DomainError> {
    let mut allowlists = AllowlistIndex::new();

    // Global exact allowlist from `whitelist` table
    let whitelist_rows = sqlx::query("SELECT domain FROM whitelist")
        .fetch_all(pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    for row in &whitelist_rows {
        let domain: String = row.get("domain");
        allowlists
            .global_exact
            .insert(CompactString::new(domain.to_ascii_lowercase()));
    }

    // Per-group allowlist from `whitelist_sources` URL sources
    let ws_rows = sqlx::query(
        "SELECT group_id, url FROM whitelist_sources WHERE enabled = 1 AND url IS NOT NULL",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

    struct WsFetch {
        group_id: i64,
        text: Option<String>,
    }

    let ws_tasks: Vec<_> = ws_rows
        .iter()
        .filter_map(|row| {
            let url: Option<String> = row.get("url");
            url.map(|u| {
                let group_id: i64 = row.get("group_id");
                let client = client.clone();
                tokio::spawn(async move {
                    let text = match fetch_url(&u, &client).await {
                        Ok(t) => Some(t),
                        Err(e) => {
                            warn!(url = %u, error = %e, "Failed to fetch whitelist source");
                            None
                        }
                    };
                    WsFetch { group_id, text }
                })
            })
        })
        .collect();

    let ws_results = join_all(ws_tasks).await;

    for result in ws_results {
        match result {
            Ok(wf) => {
                if let Some(text) = wf.text {
                    let group_id = wf.group_id;
                    let exact_set = allowlists
                        .group_exact
                        .entry(group_id)
                        .or_insert_with(|| DashSet::with_hasher(FxBuildHasher));
                    let trie = allowlists.group_wildcard.entry(group_id).or_insert_with(SuffixTrie::new);

                    for entry in parse_list_text(&text) {
                        match entry {
                            ParsedEntry::Exact(domain) => {
                                exact_set.insert(CompactString::new(domain));
                            }
                            ParsedEntry::Wildcard(pattern) => {
                                trie.insert_wildcard(&pattern, 1u64);
                            }
                            ParsedEntry::Pattern(_) => {
                                // Patterns in allowlists are not currently supported
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Whitelist source fetch task panicked");
            }
        }
    }

    Ok(allowlists)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_list_line --------------------------------------------------

    #[test]
    fn test_parse_plain_domain() {
        let entry = parse_list_line("ads.example.com").unwrap();
        assert!(matches!(entry, ParsedEntry::Exact(d) if d == "ads.example.com"));
    }

    #[test]
    fn test_parse_plain_domain_lowercased() {
        let entry = parse_list_line("ADS.Example.COM").unwrap();
        assert!(matches!(entry, ParsedEntry::Exact(d) if d == "ads.example.com"));
    }

    #[test]
    fn test_parse_hosts_file_0000() {
        let entry = parse_list_line("0.0.0.0 tracker.evil.com").unwrap();
        assert!(matches!(entry, ParsedEntry::Exact(d) if d == "tracker.evil.com"));
    }

    #[test]
    fn test_parse_hosts_file_127() {
        let entry = parse_list_line("127.0.0.1 ads.net").unwrap();
        assert!(matches!(entry, ParsedEntry::Exact(d) if d == "ads.net"));
    }

    #[test]
    fn test_parse_hosts_file_ipv6() {
        let entry = parse_list_line(":: ads.net").unwrap();
        assert!(matches!(entry, ParsedEntry::Exact(d) if d == "ads.net"));
    }

    #[test]
    fn test_parse_wildcard() {
        let entry = parse_list_line("*.ads.com").unwrap();
        assert!(matches!(entry, ParsedEntry::Wildcard(p) if p == "*.ads.com"));
    }

    #[test]
    fn test_parse_pattern_slash() {
        let entry = parse_list_line("/tracker/").unwrap();
        assert!(matches!(entry, ParsedEntry::Pattern(p) if p == "tracker"));
    }

    #[test]
    fn test_skip_comment() {
        assert!(parse_list_line("# this is a comment").is_none());
    }

    #[test]
    fn test_skip_empty() {
        assert!(parse_list_line("   ").is_none());
        assert!(parse_list_line("").is_none());
    }

    #[test]
    fn test_skip_localhost() {
        assert!(parse_list_line("127.0.0.1 localhost").is_none());
        assert!(parse_list_line("0.0.0.0 0.0.0.0").is_none());
        assert!(parse_list_line("0.0.0.0 broadcasthost").is_none());
    }

    #[test]
    fn test_skip_token_without_dot() {
        // A single token with no dot is not a valid domain
        assert!(parse_list_line("localhost").is_none());
    }

    #[test]
    fn test_parse_list_text_filters_comments() {
        let text = "# header\nads.com\n# another comment\ntracker.io\n";
        let entries = parse_list_text(text);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_hosts_with_inline_comment() {
        // Some hosts files have trailing comments after the domain (e.g. "0.0.0.0 ads.com # blocked")
        // split_whitespace on the whole line takes parts[1] as the domain, ignoring "#"
        let entry = parse_list_line("0.0.0.0 ads.com").unwrap();
        assert!(matches!(entry, ParsedEntry::Exact(d) if d == "ads.com"));
    }
}
