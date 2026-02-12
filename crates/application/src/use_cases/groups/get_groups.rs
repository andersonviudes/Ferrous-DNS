use ferrous_dns_domain::{Client, DomainError, Group};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::GroupRepository;

/// Use case for retrieving groups.
///
/// Provides methods to get all groups, get a group by ID, and get clients in a group.
pub struct GetGroupsUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl GetGroupsUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

    /// Retrieves all groups.
    ///
    /// Groups are returned sorted with the default group first, then by name.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Group>)` - All groups in the system
    /// * `Err(DomainError)` - If retrieval fails
    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<Group>, DomainError> {
        self.group_repo.get_all().await
    }

    /// Retrieves a group by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Group))` - If the group exists
    /// * `Ok(None)` - If the group doesn't exist
    /// * `Err(DomainError)` - If retrieval fails
    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError> {
        self.group_repo.get_by_id(id).await
    }

    /// Retrieves all clients in a specific group.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Client>)` - All clients in the group
    /// * `Err(DomainError)` - If retrieval fails
    #[instrument(skip(self))]
    pub async fn get_clients_in_group(&self, group_id: i64) -> Result<Vec<Client>, DomainError> {
        self.group_repo.get_clients_in_group(group_id).await
    }

    /// Counts the number of clients in a specific group.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - The number of clients in the group
    /// * `Err(DomainError)` - If counting fails
    #[instrument(skip(self))]
    pub async fn count_clients_in_group(&self, group_id: i64) -> Result<u64, DomainError> {
        self.group_repo.count_clients_in_group(group_id).await
    }
}
