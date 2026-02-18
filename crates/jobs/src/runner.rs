use crate::{ClientSyncJob, RetentionJob};
use std::sync::Arc;
use tracing::info;

/// Central orchestrator for all background jobs.
///
/// Use the builder pattern to register jobs, then call `.start()` once.
///
/// # Example
///
/// ```rust,ignore
/// JobRunner::new()
///     .with_client_sync(ClientSyncJob::new(sync_arp, sync_hostnames))
///     .with_retention(RetentionJob::new(cleanup, 30))
///     .start()
///     .await;
/// ```
pub struct JobRunner {
    client_sync: Option<ClientSyncJob>,
    retention: Option<RetentionJob>,
}

impl JobRunner {
    pub fn new() -> Self {
        Self {
            client_sync: None,
            retention: None,
        }
    }

    pub fn with_client_sync(mut self, job: ClientSyncJob) -> Self {
        self.client_sync = Some(job);
        self
    }

    pub fn with_retention(mut self, job: RetentionJob) -> Self {
        self.retention = Some(job);
        self
    }

    /// Start all registered background jobs.
    pub async fn start(self) {
        info!("Starting background job runner");

        if let Some(job) = self.client_sync {
            Arc::new(job).start().await;
        }

        if let Some(job) = self.retention {
            Arc::new(job).start().await;
        }

        info!("All background jobs started");
    }
}

impl Default for JobRunner {
    fn default() -> Self {
        Self::new()
    }
}
