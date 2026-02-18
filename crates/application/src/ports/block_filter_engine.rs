use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;

/// The outcome of a filter check for a (domain, group) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Block,
    Allow,
}

/// Application-layer port for the Block Filter Engine.
///
/// All filtering goes through this port. The implementation lives in the
/// infrastructure layer and is injected at DI time.
///
/// Hot-path methods (`resolve_group`, `check`) are synchronous — all data lives
/// in memory (DashMap, ArcSwap, thread-local LRU). Only `reload` and
/// `load_client_groups` are async because they touch the database and network.
#[async_trait]
pub trait BlockFilterEnginePort: Send + Sync {
    /// Resolve a client IP address to its group_id.
    ///
    /// Resolution order:
    ///   1. Explicit client→group DashMap (~50ns)
    ///   2. CIDR SubnetMatcher (~200ns)
    ///   3. default_group_id fallback
    fn resolve_group(&self, ip: IpAddr) -> i64;

    /// Check whether `domain` is blocked for `group_id`.
    ///
    /// The decision pipeline (all in-memory):
    ///   L0: Block Decision thread-local LRU   (~10ns hit)
    ///   L1: Block Decision shared DashMap     (~50ns hit, TTL 60s)
    ///   L2: Allowlist check (group + global)  (~50ns)
    ///   L3: Bloom filter                      (~80ns miss = Allow)
    ///   L4: Exact DashMap + bitmask           (~100ns)
    ///   L5: Suffix trie (wildcard)            (~300ns)
    ///   L6: Aho-Corasick patterns             (~1-2µs)
    fn check(&self, domain: &str, group_id: i64) -> FilterDecision;

    /// Recompile the BlockIndex from DB + HTTP sources and atomically swap it.
    /// Clears the Block Decision Cache after swap to avoid stale entries.
    async fn reload(&self) -> Result<(), DomainError>;

    /// Reload client→group assignments from the `clients` and `client_subnets`
    /// tables into the in-memory DashMap and SubnetMatcher.
    async fn load_client_groups(&self) -> Result<(), DomainError>;
}
