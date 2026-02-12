use ferrous_dns_domain::{DomainError, Group};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::GroupRepository;

/// Use case for creating a new group.
///
/// This use case validates the group name and comment, then creates the group
/// via the repository. The group is created with `enabled=true` and `is_default=false`.
pub struct CreateGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateGroupUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

    /// Creates a new group.
    ///
    /// # Arguments
    ///
    /// * `name` - The group name (1-100 characters, alphanumeric + spaces/hyphens/underscores)
    /// * `comment` - Optional descriptive comment (max 500 characters)
    ///
    /// # Returns
    ///
    /// * `Ok(Group)` - The created group
    /// * `Err(DomainError)` - If validation or creation fails
    ///
    /// # Errors
    ///
    /// * `DomainError::InvalidGroupName` - If the name is invalid or already exists
    /// * `DomainError::DatabaseError` - If a database error occurs
    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        name: String,
        comment: Option<String>,
    ) -> Result<Group, DomainError> {
        // Validate group name
        Group::validate_name(&name)?;

        // Validate comment
        Group::validate_comment(&comment.as_ref().map(|s| Arc::from(s.as_str())))?;

        // Create the group
        let group = self.group_repo.create(name.clone(), comment).await?;

        info!(
            group_id = ?group.id,
            name = %name,
            "Group created successfully"
        );

        Ok(group)
    }
}
