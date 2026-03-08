use crate::state::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

const SESSION_COOKIE_NAME: &str = "ferrous_session";

/// Middleware that requires authentication via session cookie or API token.
///
/// Authentication flow:
/// 1. If auth is disabled in config, allow all requests through.
/// 2. Check for session cookie (`ferrous_session`) → validate via `ValidateSessionUseCase`.
/// 3. Check for `X-Api-Key` header → validate via `ValidateApiTokenUseCase`.
/// 4. If neither is valid, return 401 Unauthorized.
pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !state.auth_enabled() {
        return Ok(next.run(request).await);
    }

    if let Some(session_id) = extract_session_cookie(&request) {
        if state
            .auth
            .validate_session
            .execute(&session_id)
            .await
            .is_ok()
        {
            return Ok(next.run(request).await);
        }
    }

    if let Some(token) = extract_api_token(&request) {
        if state.auth.validate_api_token.execute(&token).await.is_ok() {
            return Ok(next.run(request).await);
        }
    }

    // Also check legacy static API key
    if let Some(ref expected) = state.api_key {
        if let Some(provided) = extract_api_token(&request) {
            if crate::middleware::timing_safe_eq(provided.as_bytes(), expected.as_bytes()) {
                return Ok(next.run(request).await);
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn extract_session_cookie(request: &Request) -> Option<String> {
    let cookie_header = request.headers().get("cookie")?.to_str().ok()?;
    for part in cookie_header.split(';') {
        let trimmed = part.trim();
        if let Some(value) = trimmed.strip_prefix(SESSION_COOKIE_NAME) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_api_token(request: &Request) -> Option<String> {
    request
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}
