use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use tracing::debug;

use crate::dto::api_token::{ApiTokenResponse, CreateApiTokenRequest, CreatedApiTokenResponse};
use crate::errors::ApiError;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api-tokens", get(get_all_api_tokens))
        .route("/api-tokens", post(create_api_token))
        .route("/api-tokens/{id}", delete(delete_api_token))
}

async fn get_all_api_tokens(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiTokenResponse>>, ApiError> {
    let tokens = state.auth.get_api_tokens.get_all().await?;
    debug!(count = tokens.len(), "API tokens retrieved");
    Ok(Json(
        tokens
            .into_iter()
            .map(|t| ApiTokenResponse {
                id: t.id.unwrap_or(0),
                name: t.name.to_string(),
                key_prefix: t.key_prefix.to_string(),
                created_at: t.created_at,
                last_used_at: t.last_used_at,
            })
            .collect(),
    ))
}

async fn create_api_token(
    State(state): State<AppState>,
    Json(req): Json<CreateApiTokenRequest>,
) -> Result<(StatusCode, Json<CreatedApiTokenResponse>), ApiError> {
    let created = state.auth.create_api_token.execute(&req.name).await?;
    debug!(name = %req.name, "API token created via API");
    Ok((
        StatusCode::CREATED,
        Json(CreatedApiTokenResponse {
            id: created.token.id.unwrap_or(0),
            name: created.token.name.to_string(),
            key_prefix: created.token.key_prefix.to_string(),
            token: created.raw_token,
            created_at: created.token.created_at,
        }),
    ))
}

async fn delete_api_token(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.auth.delete_api_token.execute(id).await?;
    debug!(token_id = id, "API token deleted via API");
    Ok(StatusCode::NO_CONTENT)
}
