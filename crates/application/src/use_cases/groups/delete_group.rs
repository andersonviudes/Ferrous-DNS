use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::GroupRepository;

/// Use case for deleting a group.
///
/// This use case enforces business rules:
/// - The default "Protected" group cannot be deleted
/// - Groups with assigned clients cannot be deleted
pub struct DeleteGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl DeleteGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

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
    /// * `DomainError::ProtectedGroupCannotBeDeleted` - If attempting to delete the default group
    /// * `DomainError::GroupHasAssignedClients` - If the group has assigned clients
    /// * `DomainError::DatabaseError` - If a database error occurs
    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        // Get the group
        let group = self
            .group_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::GroupNotFound(format!(
                "Group {} not found",
                id
            )))?;

        // Business rule: Cannot delete the default "Protected" group
        if group.is_default {
            return Err(DomainError::ProtectedGroupCannotBeDeleted);
        }

        // Business rule: Cannot delete group with assigned clients
        let client_count = self.group_repo.count_clients_in_group(id).await?;
        if client_count > 0 {
            return Err(DomainError::GroupHasAssignedClients(client_count));
        }

        // Delete the group
        self.group_repo.delete(id).await?;

        info!(
            group_id = ?id,
            name = %group.name,
            "Group deleted successfully"
        );

        Ok(())
    }
}
