use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

use super::{DnsTransport, TransportResponse};

pub struct QuicTransport {
    server_addr: SocketAddr,
    hostname: Arc<str>,
}

impl QuicTransport {
    pub fn new(server_addr: SocketAddr, hostname: Arc<str>) -> Self {
        Self {
            server_addr,
            hostname,
        }
    }
}

#[async_trait]
impl DnsTransport for QuicTransport {
    async fn send(
        &self,
        _message_bytes: &[u8],
        _timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        Err(DomainError::IoError(format!(
            "DoQ upstream {}({}) not yet implemented",
            self.hostname, self.server_addr
        )))
    }

    fn protocol_name(&self) -> &'static str {
        "QUIC"
    }
}
