use async_trait::async_trait;
use ferrous_dns_domain::{Client, DomainError, Group};

/// Repository interface for managing groups.
///
/// This trait defines the contract for data access operations on groups.
/// Implementations should handle persistence, caching, and error handling.
#[async_trait]
pub trait GroupRepository: Send + Sync {
    /// Creates a new group.
    ///
    /// # Arguments
    ///
    /// * `name` - The group name (must be unique)
    /// * `comment` - Optional descriptive comment
    ///
    /// # Returns
    ///
    /// * `Ok(Group)` - The created group with generated ID and timestamps
    /// * `Err(DomainError)` - If creation fails (e.g., duplicate name)
    ///
    /// # Errors
    ///
    /// * `DomainError::InvalidGroupName` - If a group with this name already exists
    /// * `DomainError::DatabaseError` - If a database error occurs
    async fn create(&self, name: String, comment: Option<String>) -> Result<Group, DomainError>;

    /// Retrieves a group by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Group))` - If the group exists
    /// * `Ok(None)` - If no group with this ID exists
    /// * `Err(DomainError)` - If retrieval fails
    async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError>;

    /// Retrieves a group by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - The group name
    ///
    /// # Returns
    ///
    /// * `Ok(Some(Group))` - If the group exists
    /// * `Ok(None)` - If no group with this name exists
    /// * `Err(DomainError)` - If retrieval fails
    async fn get_by_name(&self, name: &str) -> Result<Option<Group>, DomainError>;

    /// Retrieves all groups.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Group>)` - All groups in the system
    /// * `Err(DomainError)` - If retrieval fails
    async fn get_all(&self) -> Result<Vec<Group>, DomainError>;

    /// Updates a group.
    ///
    /// # Arguments
    ///
    /// * `id` - The group ID
    /// * `name` - Optional new name
    /// * `enabled` - Optional new enabled status
    /// * `comment` - Optional new comment
    ///
    /// # Returns
    ///
    /// * `Ok(Group)` - The updated group
    /// * `Err(DomainError)` - If update fails
    ///
    /// # Errors
    ///
    /// * `DomainError::GroupNotFound` - If the group doesn't exist
    /// * `DomainError::InvalidGroupName` - If the new name conflicts with an existing group
    /// * `DomainError::DatabaseError` - If a database error occurs
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
    ) -> Result<Group, DomainError>;

    /// Deletes a group.
    ///
    /// # Arguments
    ///
    /// * `id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If deletion succeeds
    /// * `Err(DomainError)` - If deletion fails
    ///
    /// # Errors
    ///
    /// * `DomainError::GroupNotFound` - If the group doesn't exist
    /// * `DomainError::GroupHasAssignedClients` - If the group has clients assigned
    /// * `DomainError::DatabaseError` - If a database error occurs
    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    /// Gets all clients in a specific group.
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Client>)` - All clients in the group
    /// * `Err(DomainError)` - If retrieval fails
    async fn get_clients_in_group(&self, group_id: i64) -> Result<Vec<Client>, DomainError>;

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
    async fn count_clients_in_group(&self, group_id: i64) -> Result<u64, DomainError>;
}
