use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::GroupRepository;

/// Use case for updating a group.
///
/// This use case enforces business rules:
/// - The default "Protected" group cannot be disabled
/// - Group names must be valid and unique
/// - Comments must not exceed maximum length
pub struct UpdateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl UpdateGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

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
    /// * `DomainError::ProtectedGroupCannotBeDisabled` - If attempting to disable the default group
    /// * `DomainError::InvalidGroupName` - If the name is invalid or conflicts
    /// * `DomainError::DatabaseError` - If a database error occurs
    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
    ) -> Result<Group, DomainError> {
        // Get the existing group
        let group = self
            .group_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::GroupNotFound(format!(
                "Group {} not found",
                id
            )))?;

        // Validate name if provided
        if let Some(ref n) = name {
            Group::validate_name(n)?;
        }

        // Validate comment if provided
        if let Some(ref c) = comment {
            Group::validate_comment(&Some(Arc::from(c.as_str())))?;
        }

        // Business rule: Cannot disable the default "Protected" group
        if enabled == Some(false) && group.is_default {
            return Err(DomainError::ProtectedGroupCannotBeDisabled);
        }

        // Update the group
        let updated_group = self.group_repo.update(id, name, enabled, comment).await?;

        info!(
            group_id = ?id,
            name = %updated_group.name,
            enabled = %updated_group.enabled,
            "Group updated successfully"
        );

        Ok(updated_group)
    }
}
