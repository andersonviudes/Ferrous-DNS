use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Error returned when a string cannot be parsed as a known [`ScheduleAction`] variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownScheduleAction(pub String);

impl std::fmt::Display for UnknownScheduleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown schedule action: '{}'", self.0)
    }
}

/// Action applied to a group's DNS resolution during an active time slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleAction {
    /// Block all DNS queries for the group during this window.
    BlockAll,
    /// Allow all DNS queries for the group during this window, removing any block override.
    AllowAll,
}

impl ScheduleAction {
    /// Returns the canonical lowercase string representation used in the database and API.
    pub fn to_str(self) -> &'static str {
        match self {
            ScheduleAction::BlockAll => "block_all",
            ScheduleAction::AllowAll => "allow_all",
        }
    }
}

impl std::str::FromStr for ScheduleAction {
    type Err = UnknownScheduleAction;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "block_all" => Ok(ScheduleAction::BlockAll),
            "allow_all" => Ok(ScheduleAction::AllowAll),
            _ => Err(UnknownScheduleAction(s.to_owned())),
        }
    }
}

/// A reusable schedule profile that groups one or more [`TimeSlot`]s.
///
/// A profile can be assigned to any number of groups (via `group_schedule_profiles` table,
/// one profile per group). The scheduling engine evaluates slots every 60 seconds and
/// writes the resulting [`GroupOverride`] to the in-memory `ScheduleStateStore`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleProfile {
    /// Database row identifier. `None` before first persist.
    pub id: Option<i64>,
    /// Human-readable name. Must be unique across all profiles.
    pub name: Arc<str>,
    /// IANA timezone string (e.g. "America/Sao_Paulo", "UTC", "Europe/Lisbon").
    /// Validated at runtime by the scheduling evaluator.
    pub timezone: Arc<str>,
    /// Optional description.
    pub comment: Option<Arc<str>>,
    /// ISO-8601 creation timestamp. `None` before first persist.
    pub created_at: Option<Arc<str>>,
    /// ISO-8601 last-update timestamp. `None` before first persist.
    pub updated_at: Option<Arc<str>>,
}

impl ScheduleProfile {
    /// Validates the profile name.
    ///
    /// # Errors
    /// Returns an error string if the name is empty or exceeds 100 characters.
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("name cannot be empty".into());
        }
        if name.len() > 100 {
            return Err(format!(
                "name cannot exceed 100 characters, got {}",
                name.len()
            ));
        }
        Ok(())
    }

    /// Validates the timezone string.
    ///
    /// # Errors
    /// Returns an error string if the timezone is empty or exceeds 64 characters.
    /// Full IANA validation happens in the infrastructure evaluator at runtime.
    pub fn validate_timezone(tz: &str) -> Result<(), String> {
        if tz.is_empty() {
            return Err("timezone cannot be empty".into());
        }
        if tz.len() > 64 {
            return Err(format!(
                "timezone cannot exceed 64 characters, got {}",
                tz.len()
            ));
        }
        Ok(())
    }

    /// Validates the optional comment.
    ///
    /// # Errors
    /// Returns an error string if the comment exceeds 500 characters.
    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(c) = comment {
            if c.len() > 500 {
                return Err(format!(
                    "comment cannot exceed 500 characters, got {}",
                    c.len()
                ));
            }
        }
        Ok(())
    }
}

/// A single time window within a [`ScheduleProfile`].
///
/// Each slot independently defines which days it applies to, the time range,
/// and the action to take when the current time falls within the window.
///
/// # Conflict resolution
/// When multiple slots are active simultaneously for the same profile:
/// - If **any** active slot has `action = BlockAll`, the group is blocked.
/// - Only when **all** active slots have `action = AllowAll` is the group allowed.
///
/// This "most restrictive wins" rule is the safe default for parental controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSlot {
    /// Database row identifier. `None` before first persist.
    pub id: Option<i64>,
    /// The profile this slot belongs to.
    pub profile_id: i64,
    /// Bitmask of active days: bit0=Mon, bit1=Tue, ..., bit6=Sun. Range: 1–127.
    pub days: u8,
    /// Inclusive start time in "HH:MM" format (00:00–23:59).
    pub start_time: Arc<str>,
    /// Exclusive end time in "HH:MM" format. Must be strictly greater than `start_time`.
    pub end_time: Arc<str>,
    /// Action applied to the group's DNS resolution during this window.
    pub action: ScheduleAction,
    /// ISO-8601 creation timestamp. `None` before first persist.
    pub created_at: Option<Arc<str>>,
}

impl TimeSlot {
    /// Validates the days bitmask.
    ///
    /// # Errors
    /// Returns an error string if `days` is 0 (no day selected) or > 127.
    pub fn validate_days(days: u8) -> Result<(), String> {
        if days == 0 {
            return Err("at least one day must be selected".into());
        }
        if days > 127 {
            return Err(format!("days bitmask must be 1–127, got {days}"));
        }
        Ok(())
    }

    /// Validates a time string in "HH:MM" format.
    ///
    /// # Errors
    /// Returns an error string if the format is invalid or values are out of range.
    pub fn validate_time_format(time: &str) -> Result<(), String> {
        let parts: Vec<&str> = time.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("time must be in HH:MM format, got '{time}'"));
        }
        let hours: u8 = parts[0]
            .parse()
            .map_err(|_| format!("invalid hours in '{time}'"))?;
        let minutes: u8 = parts[1]
            .parse()
            .map_err(|_| format!("invalid minutes in '{time}'"))?;
        if hours > 23 {
            return Err(format!("hours must be 0–23, got {hours}"));
        }
        if minutes > 59 {
            return Err(format!("minutes must be 0–59, got {minutes}"));
        }
        Ok(())
    }

    /// Validates that `start_time` is strictly before `end_time`.
    ///
    /// Midnight-spanning slots (e.g. 23:00–01:00) are not supported in this version;
    /// split them into two separate slots.
    ///
    /// # Errors
    /// Returns an error string if `start_time >= end_time`.
    pub fn validate_time_range(start_time: &str, end_time: &str) -> Result<(), String> {
        if start_time >= end_time {
            return Err(format!(
                "start_time '{start_time}' must be before end_time '{end_time}'"
            ));
        }
        Ok(())
    }
}

/// Evaluates which override, if any, is active for the given weekday bitmask and time.
///
/// `weekday_bit`: bit index (0=Mon, …, 6=Sun) shifted into a bitmask (`1u8 << weekday_index`).
/// `now_time`: `"HH:MM"` in the profile's local timezone.
///
/// Conflict rule: if any active slot has `BlockAll`, returns `BlockAll` immediately.
/// Only returns `AllowAll` when at least one slot matches and none have `BlockAll`.
pub fn evaluate_slots(
    slots: &[TimeSlot],
    weekday_bit: u8,
    now_time: &str,
) -> Option<ScheduleAction> {
    let mut found_allow = false;
    for slot in slots {
        if slot.days & weekday_bit == 0 {
            continue;
        }
        if now_time < slot.start_time.as_ref() || now_time >= slot.end_time.as_ref() {
            continue;
        }
        match slot.action {
            ScheduleAction::BlockAll => return Some(ScheduleAction::BlockAll),
            ScheduleAction::AllowAll => found_allow = true,
        }
    }
    if found_allow {
        Some(ScheduleAction::AllowAll)
    } else {
        None
    }
}

/// The active DNS override state for a group, held in the in-memory `ScheduleStateStore`.
///
/// This enum is **not persisted** — it is computed by the `ScheduleEvaluatorJob` every 60
/// seconds and stored in a `DashMap<group_id, GroupOverride>` inside the engine.
///
/// The `TimedBypassUntil` and `TimedBlockUntil` variants are reserved for the upcoming
/// *Temporary domain allow/block per group (timed bypass)* feature. The engine already
/// handles them; only API + use case wiring is needed when that feature is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOverride {
    /// Block all DNS queries for this group right now (set by a BlockAll slot).
    BlockAll,
    /// Allow all DNS queries for this group right now (set by an AllowAll slot).
    AllowAll,
    /// Allow all DNS queries until the given monotonic timestamp (seconds).
    /// Reserved for the timed bypass feature.
    TimedBypassUntil(u64),
    /// Block all DNS queries until the given monotonic timestamp (seconds).
    /// Reserved for the timed bypass feature.
    TimedBlockUntil(u64),
}
