use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ScheduleProfileRepository;

/// Deletes a schedule profile along with its time slots and group assignments.
///
/// The deletion cascades via the database foreign keys, so any group that had
/// this profile assigned will revert to having no schedule.
pub struct DeleteScheduleProfileUseCase {
    repo: Arc<dyn ScheduleProfileRepository>,
}

impl DeleteScheduleProfileUseCase {
    /// Creates a new `DeleteScheduleProfileUseCase`.
    pub fn new(repo: Arc<dyn ScheduleProfileRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        self.repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ScheduleProfileNotFound(id))?;

        self.repo.delete(id).await?;

        info!(profile_id = id, "Schedule profile deleted");

        Ok(())
    }
}
