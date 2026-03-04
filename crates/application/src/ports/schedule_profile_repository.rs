use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, ScheduleAction, ScheduleProfile, TimeSlot};

/// Persistence port for schedule profiles and their time slots.
///
/// A [`ScheduleProfile`] is a reusable entity that groups one or more [`TimeSlot`]s.
/// It can be assigned to a group via the `group_schedule_profiles` join table
/// (one profile per group, enforced by the `assign_to_group` / `unassign_from_group` methods).
#[async_trait]
pub trait ScheduleProfileRepository: Send + Sync {
    // ── Profiles ──────────────────────────────────────────────────────────────

    /// Creates a new schedule profile.
    async fn create(
        &self,
        name: String,
        timezone: String,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError>;

    /// Returns the profile with the given id, or `None` if it does not exist.
    async fn get_by_id(&self, id: i64) -> Result<Option<ScheduleProfile>, DomainError>;

    /// Returns all schedule profiles ordered by name.
    async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError>;

    /// Updates a schedule profile. Only provided fields are changed.
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        timezone: Option<String>,
        comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError>;

    /// Deletes a schedule profile and cascades to its time slots and group assignments.
    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    // ── Time Slots ────────────────────────────────────────────────────────────

    /// Returns all time slots for the given profile ordered by days then start_time.
    async fn get_slots(&self, profile_id: i64) -> Result<Vec<TimeSlot>, DomainError>;

    /// Adds a time slot to the given profile.
    async fn add_slot(
        &self,
        profile_id: i64,
        days: u8,
        start_time: String,
        end_time: String,
        action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError>;

    /// Deletes a single time slot by id.
    async fn delete_slot(&self, slot_id: i64) -> Result<(), DomainError>;

    // ── Group Assignments ─────────────────────────────────────────────────────

    /// Assigns (or replaces) the schedule profile for a group.
    /// Replaces any existing assignment for that group.
    async fn assign_to_group(&self, group_id: i64, profile_id: i64) -> Result<(), DomainError>;

    /// Removes the schedule profile assignment from a group.
    /// No-op if the group has no profile assigned.
    async fn unassign_from_group(&self, group_id: i64) -> Result<(), DomainError>;

    /// Returns the profile id assigned to the group, or `None` if unassigned.
    async fn get_group_assignment(&self, group_id: i64) -> Result<Option<i64>, DomainError>;

    /// Returns all `(group_id, profile_id)` pairs.
    /// Used by the `ScheduleEvaluatorJob` to evaluate all active schedules.
    async fn get_all_group_assignments(&self) -> Result<Vec<(i64, i64)>, DomainError>;
}
