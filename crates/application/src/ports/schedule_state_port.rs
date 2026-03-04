use ferrous_dns_domain::GroupOverride;

/// In-memory store for active DNS override states per group.
///
/// This port is implemented by `ScheduleStateStore` (a lock-free `DashMap`).
/// It is shared between:
///
/// - **`ScheduleEvaluatorJob`** — writes overrides every 60 s based on active time slots.
/// - **`BlockFilterEngine`** — reads overrides on every DNS query (hot path, must be O(1)).
/// - **Future: timed bypass API handlers** — write `TimedBypassUntil` / `TimedBlockUntil`
///   overrides via `SetGroupOverrideUseCase`.
///
/// Overrides are **never persisted**. They are recomputed from the database on every
/// evaluation tick, and lost on server restart (the evaluator re-populates them within 60 s).
pub trait ScheduleStatePort: Send + Sync {
    /// Returns the current override for a group, or `None` if no override is active.
    fn get(&self, group_id: i64) -> Option<GroupOverride>;

    /// Sets an override for a group. Replaces any existing override.
    fn set(&self, group_id: i64, state: GroupOverride);

    /// Removes the override for a group, restoring normal DNS filtering behaviour.
    fn clear(&self, group_id: i64);

    /// Returns `true` if no overrides are currently set.
    ///
    /// Used by `BlockFilterEngine::check()` to skip the DashMap lookup entirely
    /// when no schedules are configured — keeping the hot path at zero cost.
    fn is_empty(&self) -> bool;

    /// Removes all expired `TimedBypassUntil` and `TimedBlockUntil` overrides.
    ///
    /// Called by `ScheduleEvaluatorJob` on every tick. This allows timed bypass
    /// overrides to expire automatically without a dedicated cleanup job.
    fn sweep_expired(&self);
}
