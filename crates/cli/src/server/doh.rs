use axum::extract::{Query, Request};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use base64::Engine;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::IpAddr;
use std::sync::Arc;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(serde::Deserialize)]
pub struct DnsQueryParams {
    dns: Option<String>,
}

/// DNS-over-HTTPS handler (RFC 8484).
///
/// Accepts both `GET /dns-query?dns=<base64url>` and
/// `POST /dns-query` with `Content-Type: application/dns-message`.
/// Client IP is extracted from proxy headers (`X-Real-IP`, `X-Forwarded-For`)
/// so blocklist and analytics correctly attribute requests forwarded via reverse proxy.
///
/// The handler is injected via `Extension` to avoid a state-type conflict with
/// the main Axum router that uses `AppState`.
pub async fn dns_query_handler(
    Extension(handler): Extension<Arc<DnsServerHandler>>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
    request: Request,
) -> Response {
    let client_ip = extract_client_ip(&headers);

    let wire = if *request.method() == Method::POST {
        match axum::body::to_bytes(request.into_body(), 65_535).await {
            Ok(b) => b.to_vec(),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        match params.dns.as_deref() {
            Some(encoded) => match decode_base64url(encoded) {
                Ok(b) => b,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            },
            None => return StatusCode::BAD_REQUEST.into_response(),
        }
    };

    match handler.handle_raw_udp_fallback(&wire, client_ip).await {
        Some(response_bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)],
            response_bytes,
        )
            .into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn extract_client_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}
