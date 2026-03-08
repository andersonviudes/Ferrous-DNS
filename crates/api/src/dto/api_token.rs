use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateApiTokenRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreatedApiTokenResponse {
    pub id: i64,
    pub name: String,
    pub key_prefix: String,
    pub token: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiTokenResponse {
    pub id: i64,
    pub name: String,
    pub key_prefix: String,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}
