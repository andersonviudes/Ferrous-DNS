use ferrous_dns_application::use_cases::{
    AssignClientGroupUseCase, CreateGroupUseCase, DeleteGroupUseCase, GetBlocklistUseCase,
    GetClientsUseCase, GetGroupsUseCase, GetQueryStatsUseCase, GetRecentQueriesUseCase,
    UpdateGroupUseCase,
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{cache::DnsCache, HickoryDnsResolver};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub get_stats: Arc<GetQueryStatsUseCase>,
    pub get_queries: Arc<GetRecentQueriesUseCase>,
    pub get_blocklist: Arc<GetBlocklistUseCase>,
    pub get_clients: Arc<GetClientsUseCase>,
    pub get_groups: Arc<GetGroupsUseCase>,
    pub create_group: Arc<CreateGroupUseCase>,
    pub update_group: Arc<UpdateGroupUseCase>,
    pub delete_group: Arc<DeleteGroupUseCase>,
    pub assign_client_group: Arc<AssignClientGroupUseCase>,
    pub config: Arc<RwLock<Config>>,
    pub cache: Arc<DnsCache>,
    pub dns_resolver: Arc<HickoryDnsResolver>,
}
