use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Represents a logical group for organizing network clients.
///
/// Groups allow administrators to categorize clients (e.g., "Guest Devices",
/// "IoT Devices") and apply policies, filters, or organizational structure.
///
/// # Special Groups
///
/// The "Protected" group (identified by `is_default = true`) has special
/// constraints:
/// - Cannot be disabled
/// - Cannot be deleted
/// - All new clients are assigned to this group by default
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier (database primary key)
    pub id: Option<i64>,

    /// Group name (must be unique across all groups)
    pub name: Arc<str>,

    /// Whether the group is enabled/active
    pub enabled: bool,

    /// Optional descriptive comment
    pub comment: Option<Arc<str>>,

    /// Indicates if this is the default/protected group
    /// Only one group can have this flag set to true
    pub is_default: bool,

    /// Timestamp when the group was created
    pub created_at: Option<String>,

    /// Timestamp when the group was last updated
    pub updated_at: Option<String>,
}

impl Group {
    /// Creates a new Group instance.
    ///
    /// # Arguments
    ///
    /// * `id` - Optional database ID
    /// * `name` - Group name (must be 1-100 characters)
    /// * `enabled` - Whether the group is active
    /// * `comment` - Optional descriptive comment
    /// * `is_default` - Whether this is the default/protected group
    ///
    /// # Examples
    ///
    /// ```
    /// use ferrous_dns_domain::Group;
    /// use std::sync::Arc;
    ///
    /// let group = Group::new(
    ///     None,
    ///     Arc::from("Guest Devices"),
    ///     true,
    ///     Some(Arc::from("Temporary network access")),
    ///     false
    /// );
    /// ```
    pub fn new(
        id: Option<i64>,
        name: Arc<str>,
        enabled: bool,
        comment: Option<Arc<str>>,
        is_default: bool,
    ) -> Self {
        Self {
            id,
            name,
            enabled,
            comment,
            is_default,
            created_at: None,
            updated_at: None,
        }
    }

    /// Checks if this group can be disabled.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the group can be disabled
    /// * `Err(())` if the group is the default group and cannot be disabled
    ///
    /// # Examples
    ///
    /// ```
    /// use ferrous_dns_domain::Group;
    /// use std::sync::Arc;
    ///
    /// let protected = Group::new(None, Arc::from("Protected"), true, None, true);
    /// assert!(protected.can_disable().is_err());
    ///
    /// let regular = Group::new(None, Arc::from("Regular"), true, None, false);
    /// assert!(regular.can_disable().is_ok());
    /// ```
    pub fn can_disable(&self) -> Result<(), ()> {
        if self.is_default {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Checks if this group can be deleted.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the group can be deleted
    /// * `Err(())` if the group is the default group and cannot be deleted
    ///
    /// # Examples
    ///
    /// ```
    /// use ferrous_dns_domain::Group;
    /// use std::sync::Arc;
    ///
    /// let protected = Group::new(None, Arc::from("Protected"), true, None, true);
    /// assert!(protected.can_delete().is_err());
    ///
    /// let regular = Group::new(None, Arc::from("Regular"), true, None, false);
    /// assert!(regular.can_delete().is_ok());
    /// ```
    pub fn can_delete(&self) -> Result<(), ()> {
        if self.is_default {
            Err(())
        } else {
            Ok(())
        }
    }

    /// Validates the group name.
    ///
    /// # Rules
    ///
    /// * Must be between 1 and 100 characters
    /// * Must contain only alphanumeric characters, spaces, hyphens, or underscores
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the name is valid
    /// * `Err(String)` with error message if the name is invalid
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Group name cannot be empty".to_string());
        }

        if name.len() > 100 {
            return Err("Group name cannot exceed 100 characters".to_string());
        }

        let valid_chars = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');

        if !valid_chars {
            return Err(
                "Group name can only contain alphanumeric characters, spaces, hyphens, and underscores"
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Validates the comment field.
    ///
    /// # Rules
    ///
    /// * Must not exceed 500 characters if present
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the comment is valid or None
    /// * `Err(String)` with error message if the comment is too long
    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(c) = comment {
            if c.len() > 500 {
                return Err("Comment cannot exceed 500 characters".to_string());
            }
        }
        Ok(())
    }
}

/// Statistics about groups in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStats {
    /// Total number of groups
    pub total_groups: u64,

    /// Number of enabled groups
    pub enabled_groups: u64,

    /// Number of disabled groups
    pub disabled_groups: u64,

    /// Total number of clients assigned to groups
    pub total_clients: u64,
}

impl Default for GroupStats {
    fn default() -> Self {
        Self {
            total_groups: 0,
            enabled_groups: 0,
            disabled_groups: 0,
            total_clients: 0,
        }
    }
}
