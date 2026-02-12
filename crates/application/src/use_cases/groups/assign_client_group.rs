use ferrous_dns_domain::{Client, DomainError};
use std::sync::Arc;
use tracing::{info, instrument, warn};

use crate::ports::{ClientRepository, GroupRepository};

/// Use case for assigning a client to a group.
///
/// This use case validates that both the client and group exist before
/// performing the assignment.
pub struct AssignClientGroupUseCase {
    client_repo: Arc<dyn ClientRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl AssignClientGroupUseCase {
    pub fn new(
        client_repo: Arc<dyn ClientRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self {
            client_repo,
            group_repo,
        }
    }

    /// Assigns a client to a group.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client ID
    /// * `group_id` - The group ID
    ///
    /// # Returns
    ///
    /// * `Ok(Client)` - The updated client
    /// * `Err(DomainError)` - If assignment fails
    ///
    /// # Errors
    ///
    /// * `DomainError::NotFound` - If the client doesn't exist
    /// * `DomainError::GroupNotFound` - If the group doesn't exist
    /// * `DomainError::DatabaseError` - If a database error occurs
    ///
    /// # Notes
    ///
    /// Assigning a client to a disabled group will succeed but a warning
    /// will be logged. This allows for group reorganization without
    /// affecting client tracking.
    #[instrument(skip(self))]
    pub async fn execute(&self, client_id: i64, group_id: i64) -> Result<Client, DomainError> {
        // Verify the group exists
        let group = self
            .group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(format!(
                "Group {} not found",
                group_id
            )))?;

        // Verify the client exists
        let _client = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::NotFound(format!(
                "Client {} not found",
                client_id
            )))?;

        // Warn if assigning to a disabled group
        if !group.enabled {
            warn!(
                client_id = client_id,
                group_id = group_id,
                group_name = %group.name,
                "Assigning client to disabled group"
            );
        }

        // Assign the client to the group
        self.client_repo
            .assign_group(client_id, group_id)
            .await?;

        // Return the updated client
        let updated_client = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::NotFound(format!(
                "Client {} not found after update",
                client_id
            )))?;

        info!(
            client_id = client_id,
            group_id = group_id,
            group_name = %group.name,
            "Client assigned to group successfully"
        );

        Ok(updated_client)
    }
}
