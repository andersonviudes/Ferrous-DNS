use std::sync::Arc;

/// An authenticated browser session, stored in SQLite.
///
/// Sessions use `HttpOnly; SameSite=Strict` cookies. TTL depends on whether
/// the user checked "Remember Me" at login:
/// - Without: `session_ttl_hours` (default 24h)
/// - With: `remember_me_days` (default 30 days)
///
/// There is no concurrent session limit.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub id: Arc<str>,
    pub username: Arc<str>,
    pub role: Arc<str>,
    pub ip_address: Arc<str>,
    pub user_agent: Arc<str>,
    pub remember_me: bool,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
}

impl AuthSession {
    pub fn new(
        id: Arc<str>,
        username: Arc<str>,
        role: Arc<str>,
        ip_address: Arc<str>,
        user_agent: Arc<str>,
        remember_me: bool,
        expires_at: String,
    ) -> Self {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        Self {
            id,
            username,
            role,
            ip_address,
            user_agent,
            remember_me,
            created_at: now.clone(),
            last_seen_at: now,
            expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::NaiveDateTime::parse_from_str(&self.expires_at, "%Y-%m-%d %H:%M:%S")
            .map(|exp| {
                let now = chrono::Utc::now().naive_utc();
                now > exp
            })
            .unwrap_or(true)
    }
}
