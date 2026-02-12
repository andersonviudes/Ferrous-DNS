use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub enabled: bool,
    pub comment: Option<Arc<str>>,
    pub is_default: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl Group {
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

    pub fn can_disable(&self) -> Result<(), ()> {
        if self.is_default {
            Err(())
        } else {
            Ok(())
        }
    }

    pub fn can_delete(&self) -> Result<(), ()> {
        if self.is_default {
            Err(())
        } else {
            Ok(())
        }
    }

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

    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(c) = comment {
            if c.len() > 500 {
                return Err("Comment cannot exceed 500 characters".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStats {
    pub total_groups: u64,
    pub enabled_groups: u64,
    pub disabled_groups: u64,
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
