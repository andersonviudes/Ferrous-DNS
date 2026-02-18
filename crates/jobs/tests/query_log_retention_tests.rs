use ferrous_dns_application::use_cases::CleanupOldQueryLogsUseCase;
use ferrous_dns_jobs::QueryLogRetentionJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

mod helpers;
use helpers::MockQueryLogRepository;

// ============================================================================
// Tests: CleanupOldQueryLogsUseCase (business logic)
// ============================================================================

#[tokio::test]
async fn test_cleanup_removes_old_logs() {
    // Arrange - one recent, one 40 days old
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("192.168.1.1").await;
    repo.add_old_log("192.168.1.2", 40).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    // Act - retain 30 days
    let result = use_case.execute(30).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1); // 1 deleted
    assert_eq!(repo.count().await, 1); // 1 remaining
}

#[tokio::test]
async fn test_cleanup_empty_repository() {
    let repo = Arc::new(MockQueryLogRepository::new());
    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    let result = use_case.execute(30).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_preserves_recent_logs() {
    // Arrange - all logs are recent
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("10.0.0.1").await;
    repo.add_recent_log("10.0.0.2").await;
    repo.add_recent_log("10.0.0.3").await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert - nothing deleted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(repo.count().await, 3);
}

#[tokio::test]
async fn test_cleanup_all_old_logs() {
    // Arrange - all logs are old
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 31).await;
    repo.add_old_log("10.0.0.2", 60).await;
    repo.add_old_log("10.0.0.3", 90).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert - all deleted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_mixed_logs() {
    // Arrange - 2 recent, 3 old
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("192.168.1.1").await;
    repo.add_recent_log("192.168.1.2").await;
    repo.add_old_log("192.168.1.3", 40).await;
    repo.add_old_log("192.168.1.4", 55).await;
    repo.add_old_log("192.168.1.5", 100).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert - 3 old deleted, 2 recent remain
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.count().await, 2);
}

#[tokio::test]
async fn test_cleanup_with_boundary_unambiguous() {
    // Arrange - 25 days old (within 30-day window) vs 40 days old (outside)
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("192.168.1.1", 25).await; // within window
    repo.add_old_log("192.168.1.2", 40).await; // outside window

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    // Act
    let result = use_case.execute(30).await;

    // Assert - only the 40-day log deleted
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_cleanup_idempotent() {
    // Arrange
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 60).await;

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());

    // Act - run twice
    let result1 = use_case.execute(30).await;
    let result2 = use_case.execute(30).await;

    // Assert - second run deletes nothing
    assert_eq!(result1.unwrap(), 1);
    assert_eq!(result2.unwrap(), 0);
    assert_eq!(repo.count().await, 0);
}

#[tokio::test]
async fn test_cleanup_configurable_retention_short() {
    // 7-day retention removes more
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 3).await; // 3 days old - within 7d window
    repo.add_old_log("10.0.0.2", 10).await; // 10 days old - outside 7d window

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());
    let result = use_case.execute(7).await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

#[tokio::test]
async fn test_cleanup_configurable_retention_long() {
    // 90-day retention keeps more
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 60).await; // 60 days - within 90d window
    repo.add_old_log("10.0.0.2", 100).await; // 100 days - outside 90d window

    let use_case = CleanupOldQueryLogsUseCase::new(repo.clone());
    let result = use_case.execute(90).await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(repo.count().await, 1);
}

// ============================================================================
// Tests: QueryLogRetentionJob scheduling
// ============================================================================

#[tokio::test]
async fn test_query_log_retention_job_starts_without_panic() {
    let repo = Arc::new(MockQueryLogRepository::new());
    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 30));

    // Should not panic
    job.start().await;
    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_query_log_retention_job_fires_and_cleans() {
    // Arrange - old log + short interval
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("192.168.1.100", 60).await;

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 30).with_interval(1));

    // Act
    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    // Assert - old log cleaned up by the job
    assert_eq!(
        repo.count().await,
        0,
        "QueryLogRetentionJob should have cleaned up the old log"
    );
}

#[tokio::test]
async fn test_query_log_retention_job_preserves_recent_logs() {
    // Arrange - only recent logs
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("192.168.1.1").await;
    repo.add_recent_log("192.168.1.2").await;

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 30).with_interval(1));

    // Act
    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    // Assert - recent logs untouched
    assert_eq!(repo.count().await, 2);
}

#[tokio::test]
async fn test_query_log_retention_job_respects_configured_days() {
    // Arrange - logs at different ages, using 7-day retention
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 3).await; // within 7d - should stay
    repo.add_old_log("10.0.0.2", 10).await; // outside 7d - should be deleted

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    let job = Arc::new(QueryLogRetentionJob::new(use_case, 7).with_interval(1));

    // Act
    job.start().await;
    sleep(Duration::from_millis(1100)).await;

    // Assert - only the 10-day log was deleted
    assert_eq!(repo.count().await, 1);
}
