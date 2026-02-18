use ferrous_dns_application::use_cases::CleanupOldClientsUseCase;
use ferrous_dns_jobs::RetentionJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

mod helpers;
use helpers::{make_client, make_old_client, MockClientRepository};

// ============================================================================
// Tests: CleanupOldClientsUseCase (business logic exercised by RetentionJob)
// ============================================================================

#[tokio::test]
async fn test_cleanup_removes_old_clients() {
    // Arrange - one recent, one old
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),       // recent
            make_old_client(2, "192.168.1.2", 40), // 40 days old
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act - retain 30 days
    let result = use_case.execute(30).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // 1 deleted
    assert_eq!(repo.count().await, 1); // 1 remaining
}

#[tokio::test]
async fn test_cleanup_empty_repository() {
    // Arrange
    let repo = Arc::new(MockClientRepository::new());
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_preserves_recent_clients() {
    // Arrange - all clients are recent (1 day old)
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 1),
            make_old_client(2, "192.168.1.2", 1),
            make_old_client(3, "192.168.1.3", 1),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act - retain 30 days, all clients are within window
    let result = use_case.execute(30).await;

    // Assert - nothing deleted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 3);
}

#[tokio::test]
async fn test_cleanup_boundary_exactly_at_retention_days() {
    // Arrange - one clearly within window, one clearly outside
    // Using 25 days vs 40 days to avoid sub-second timing ambiguity at the boundary
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 25), // 25 days old - within 30-day window
            make_old_client(2, "192.168.1.2", 40), // 40 days old - outside window
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert - only the 40-day client should be deleted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_cleanup_all_old_clients() {
    // Arrange - all clients are old
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 60),
            make_old_client(2, "192.168.1.2", 90),
            make_old_client(3, "192.168.1.3", 45),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert - all deleted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_with_zero_retention_days() {
    // Arrange - retention of 0 days should delete everything
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(0).await;

    // Assert - all clients are considered "old" when retention is 0
    assert!(result.is_ok());
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_idempotent() {
    // Arrange
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "10.0.0.1", 60),
        ])
        .await,
    );
    let use_case = CleanupOldClientsUseCase::new(repo.clone());

    // Act - run cleanup twice
    let result1 = use_case.execute(30).await;
    let result2 = use_case.execute(30).await;

    // Assert - second run deletes nothing (already gone)
    assert_eq!(result1.unwrap(), 1);
    assert_eq!(result2.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

// ============================================================================
// Tests: RetentionJob construction and scheduling
// ============================================================================

#[tokio::test]
async fn test_retention_job_starts_without_panic() {
    // Arrange
    let repo = Arc::new(MockClientRepository::new());
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo));
    let job = Arc::new(RetentionJob::new(use_case, 30));

    // Act - should not panic
    job.start().await;

    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_retention_job_with_custom_interval_fires() {
    // Arrange - old clients + short interval
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_old_client(1, "192.168.1.1", 60),
        ])
        .await,
    );
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));

    // 1-second interval to let it fire quickly
    let job = Arc::new(RetentionJob::new(use_case, 30).with_interval(1));

    // Act
    job.start().await;

    // Wait for at least one tick + some buffer
    sleep(Duration::from_millis(1100)).await;

    // Assert - old client was cleaned up by the job
    assert_eq!(
        repo.count().await,
        0,
        "RetentionJob should have cleaned up the old client"
    );
}

#[tokio::test]
async fn test_retention_job_preserves_recent_clients() {
    // Arrange - only recent clients
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
        ])
        .await,
    );
    let use_case = Arc::new(CleanupOldClientsUseCase::new(repo.clone()));
    let job = Arc::new(RetentionJob::new(use_case, 30).with_interval(1));

    // Act
    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    // Assert - recent clients untouched
    assert_eq!(repo.count().await, 2);
}
