use super::block_index::BlockIndex;
use super::compiler::compile_block_index;
use super::decision_cache::{
    decision_l0_clear, decision_l0_get, decision_l0_set, BlockDecisionCache,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::{ClientSubnet, DomainError, SubnetMatcher};
use lru::LruCache;
use rustc_hash::FxBuildHasher;
use sqlx::{Row, SqlitePool};
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Thread-local group resolution cache (L−1)
// ---------------------------------------------------------------------------

/// Per-thread LRU mapping IP → (group_id, expiry).
///
/// Avoids the DashMap + ArcSwap + CIDR scan (~250 ns) on every query.
/// TTL of 60 s matches the client-group reload cadence.
type GroupL0Cache = LruCache<IpAddr, (i64, Instant), FxBuildHasher>;

thread_local! {
    static GROUP_L0: RefCell<GroupL0Cache> =
        RefCell::new(LruCache::with_hasher(
            NonZeroUsize::new(32).unwrap(),
            FxBuildHasher,
        ));
}

/// The Block Filter Engine.
///
/// All filtering state lives in memory. The compiled `BlockIndex` is swapped
/// atomically via `ArcSwap` during `reload()` — no downtime, no lock contention.
///
/// Group resolution order:
///   1. Explicit client → group DashMap (~50 ns)
///   2. CIDR SubnetMatcher (~200 ns)
///   3. Default group id fallback
pub struct BlockFilterEngine {
    /// Current compiled block index. Swapped atomically on reload.
    index: ArcSwap<BlockIndex>,

    /// Shared Block Decision Cache (L1). Cleared after each index swap.
    decision_cache: BlockDecisionCache,

    /// Explicit IP → group_id mapping loaded from the `clients` table.
    client_groups: Arc<DashMap<IpAddr, i64, FxBuildHasher>>,

    /// CIDR-based subnet → group_id mapping. Replaced atomically.
    subnet_matcher: ArcSwap<Option<SubnetMatcher>>,

    /// Fallback group used when no explicit or subnet match is found.
    default_group_id: i64,

    /// Database connection pool (used in `reload` and `load_client_groups`).
    pool: SqlitePool,

    /// Persistent HTTP client. Avoids recreating the connection pool on reload.
    http_client: reqwest::Client,
}

impl BlockFilterEngine {
    /// Create and initialise the engine.
    ///
    /// Compiles the initial `BlockIndex` from the database and any HTTP sources.
    /// Also loads the initial client→group assignments.
    pub async fn new(pool: SqlitePool, default_group_id: i64) -> Result<Self, DomainError> {
        let http_client = reqwest::Client::builder()
            .user_agent("Ferrous-DNS/1.0 (blocklist-sync)")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| DomainError::BlockFilterCompileError(e.to_string()))?;

        info!("Block filter compilation started");
        let index = compile_block_index(&pool, &http_client).await?;
        info!("BlockFilterEngine initialized");

        let engine = Self {
            index: ArcSwap::from_pointee(index),
            decision_cache: BlockDecisionCache::new(),
            client_groups: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            subnet_matcher: ArcSwap::from_pointee(None),
            default_group_id,
            pool,
            http_client,
        };

        engine.load_client_groups_inner().await?;

        Ok(engine)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Resolve a client IP to its group_id without consulting the thread-local cache.
    fn resolve_group_uncached(&self, ip: IpAddr) -> i64 {
        // 1. Explicit mapping
        if let Some(gid) = self.client_groups.get(&ip) {
            return *gid;
        }

        // 2. CIDR subnet
        let guard = self.subnet_matcher.load();
        if let Some(matcher) = guard.as_ref() {
            if let Some(gid) = matcher.find_group_for_ip(ip) {
                return gid;
            }
        }

        // 3. Default
        self.default_group_id
    }

    /// Load/reload client→group and subnet→group assignments from the DB.
    async fn load_client_groups_inner(&self) -> Result<(), DomainError> {
        // Explicit IP → group_id
        let client_rows =
            sqlx::query("SELECT ip_address, group_id FROM clients WHERE group_id IS NOT NULL")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        self.client_groups.clear();
        for row in &client_rows {
            let ip_str: String = row.get("ip_address");
            let group_id: i64 = row.get("group_id");
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                self.client_groups.insert(ip, group_id);
            }
        }

        // CIDR subnets → group_id
        let subnet_rows = sqlx::query(
            "SELECT subnet_cidr, group_id FROM client_subnets ORDER BY length(subnet_cidr) DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        let subnets: Vec<ClientSubnet> = subnet_rows
            .iter()
            .map(|row| ClientSubnet {
                id: None,
                subnet_cidr: Arc::from(row.get::<String, _>("subnet_cidr").as_str()),
                group_id: row.get("group_id"),
                comment: None,
                created_at: None,
                updated_at: None,
            })
            .collect();

        let matcher = match SubnetMatcher::new(subnets) {
            Ok(m) => Some(m),
            Err(e) => {
                warn!(error = %e, "Failed to build SubnetMatcher; CIDR-based group lookup disabled");
                None
            }
        };
        self.subnet_matcher.store(Arc::new(matcher));

        info!(clients = client_rows.len(), "Client groups loaded");

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BlockFilterEnginePort implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl BlockFilterEnginePort for BlockFilterEngine {
    /// Resolve a client IP to its group_id.
    ///
    /// Resolution order:
    ///   L−1: thread-local LRU (TTL 60 s)  (~10 ns hit, ≥99% after warmup)
    ///   1.   Explicit DashMap              (~50 ns)
    ///   2.   CIDR SubnetMatcher            (~200 ns)
    ///   3.   Default group fallback
    #[inline]
    fn resolve_group(&self, ip: IpAddr) -> i64 {
        // L−1: thread-local cache
        if let Some(gid) = GROUP_L0.with(|c| {
            let mut cache = c.borrow_mut();
            if let Some(&(gid, expires)) = cache.get(&ip) {
                if Instant::now() < expires {
                    return Some(gid);
                }
                cache.pop(&ip);
            }
            None
        }) {
            return gid;
        }

        let gid = self.resolve_group_uncached(ip);
        GROUP_L0.with(|c| {
            c.borrow_mut()
                .put(ip, (gid, Instant::now() + Duration::from_secs(60)));
        });
        gid
    }

    /// Check whether `domain` is blocked for `group_id`.
    ///
    /// Decision pipeline:
    ///   L0: thread-local LRU           (~10 ns)
    ///   L1: shared DashMap (TTL 60 s)  (~50 ns)
    ///   L2+: BlockIndex pipeline       (~80–2000 ns)
    #[inline]
    fn check(&self, domain: &str, group_id: i64) -> FilterDecision {
        // L0: thread-local
        if let Some(blocked) = decision_l0_get(domain, group_id) {
            return if blocked {
                FilterDecision::Block
            } else {
                FilterDecision::Allow
            };
        }

        // L1: shared DashMap
        if let Some(blocked) = self.decision_cache.get(domain, group_id) {
            decision_l0_set(domain, group_id, blocked);
            return if blocked {
                FilterDecision::Block
            } else {
                FilterDecision::Allow
            };
        }

        // L2+: full BlockIndex pipeline
        let guard = self.index.load();
        let blocked = guard.is_blocked(domain, group_id);

        // Populate both caches
        self.decision_cache.set(domain, group_id, blocked);
        decision_l0_set(domain, group_id, blocked);

        if blocked {
            FilterDecision::Block
        } else {
            FilterDecision::Allow
        }
    }

    /// Recompile the `BlockIndex` from DB + HTTP and atomically swap it.
    ///
    /// After swapping, the shared Decision Cache (L1) is cleared so stale
    /// decisions do not persist. The per-thread L0 caches are cleared on the
    /// calling thread; other threads will naturally expire stale entries via TTL.
    async fn reload(&self) -> Result<(), DomainError> {
        info!("Block filter reload started");

        let new_index = compile_block_index(&self.pool, &self.http_client)
            .await
            .map_err(|e| {
                error!(error = %e, "Block filter reload failed");
                e
            })?;

        self.index.store(Arc::new(new_index));

        // Clear caches after swap
        self.decision_cache.clear();
        decision_l0_clear();

        info!("Block filter reload completed");
        Ok(())
    }

    /// Reload client→group assignments from the `clients` and `client_subnets` tables.
    async fn load_client_groups(&self) -> Result<(), DomainError> {
        self.load_client_groups_inner().await
    }

    fn compiled_domain_count(&self) -> usize {
        self.index.load().total_blocked_domains
    }
}
