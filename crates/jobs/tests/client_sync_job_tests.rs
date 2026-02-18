use ferrous_dns_application::use_cases::{SyncArpCacheUseCase, SyncHostnamesUseCase};
use ferrous_dns_jobs::ClientSyncJob;
use std::sync::Arc;
use tokio::time::{Duration, sleep};

mod helpers;
use helpers::{make_client, MockArpReader, MockClientRepository, MockHostnameResolver};

// ============================================================================
// Tests: SyncArpCacheUseCase (business logic exercised by ClientSyncJob)
// ============================================================================

#[tokio::test]
async fn test_arp_sync_updates_known_clients() {
    // Arrange - client exists, ARP table has its MAC
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![make_client(1, "192.168.1.10")]).await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("192.168.1.10", "aa:bb:cc:dd:ee:ff"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp.clone(), repo.clone());

    // Act
    let result = use_case.execute().await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    let client = repo.get_client_by_ip("192.168.1.10").await.unwrap();
    assert_eq!(
        client.mac_address.as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
}

#[tokio::test]
async fn test_arp_sync_empty_table_returns_zero() {
    // Arrange - no ARP entries
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let use_case = SyncArpCacheUseCase::new(arp, repo);

    // Act
    let result = use_case.execute().await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_arp_sync_unknown_ip_skipped() {
    // Arrange - ARP table has IP not in repo
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("10.0.0.99", "ff:ee:dd:cc:bb:aa"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp, repo.clone());

    // Act
    let result = use_case.execute().await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0); // No clients updated (IP not tracked)
}

#[tokio::test]
async fn test_arp_sync_multiple_entries() {
    // Arrange
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
            make_client(3, "192.168.1.3"),
        ])
        .await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("192.168.1.1", "aa:aa:aa:aa:aa:01"),
        ("192.168.1.2", "aa:aa:aa:aa:aa:02"),
        ("192.168.1.3", "aa:aa:aa:aa:aa:03"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp, repo.clone());

    // Act
    let result = use_case.execute().await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 3);
    assert_eq!(repo.mac_update_count(), 3);
}

#[tokio::test]
async fn test_arp_sync_partial_match() {
    // Arrange - 3 clients, only 2 in ARP table
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![
            make_client(1, "192.168.1.1"),
            make_client(2, "192.168.1.2"),
            make_client(3, "192.168.1.3"),
        ])
        .await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("192.168.1.1", "aa:bb:cc:00:00:01"),
        ("192.168.1.2", "aa:bb:cc:00:00:02"),
    ]));
    let use_case = SyncArpCacheUseCase::new(arp, repo.clone());

    // Act
    let result = use_case.execute().await;

    // Assert - only 2 updated
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 2);

    // Client 3 remains without MAC
    let client3 = repo.get_client_by_ip("192.168.1.3").await.unwrap();
    assert!(client3.mac_address.is_none());
}

// ============================================================================
// Tests: SyncHostnamesUseCase (business logic exercised by ClientSyncJob)
// ============================================================================

#[tokio::test]
async fn test_hostname_sync_resolves_known_clients() {
    // Arrange
    let client = make_client(1, "192.168.1.50");
    let repo = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver
        .set_response("192.168.1.50", Some("my-device.local"))
        .await;

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver);

    // Act
    let result = use_case.execute(10).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    let client = repo.get_client_by_ip("192.168.1.50").await.unwrap();
    assert_eq!(client.hostname.as_deref(), Some("my-device.local"));
}

#[tokio::test]
async fn test_hostname_sync_no_ptr_record_skips_client() {
    // Arrange - resolver returns None (no PTR)
    let client = make_client(1, "192.168.1.60");
    let repo = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver.set_response("192.168.1.60", None).await;

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver);

    // Act
    let result = use_case.execute(10).await;

    // Assert - no hostnames resolved (PTR returned None)
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    let client = repo.get_client_by_ip("192.168.1.60").await.unwrap();
    assert!(client.hostname.is_none());
}

#[tokio::test]
async fn test_hostname_sync_empty_repository() {
    // Arrange - no clients
    let repo = Arc::new(MockClientRepository::new());
    let resolver = Arc::new(MockHostnameResolver::new());
    let use_case = SyncHostnamesUseCase::new(repo, resolver.clone());

    // Act
    let result = use_case.execute(10).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
    assert_eq!(resolver.call_count(), 0); // Resolver never called
}

#[tokio::test]
async fn test_hostname_sync_respects_batch_size() {
    // Arrange - 5 clients without hostname, batch_size = 3
    let clients = (1..=5)
        .map(|i| make_client(i, &format!("192.168.1.{}", i + 10)))
        .collect();
    let repo = Arc::new(MockClientRepository::with_clients(clients).await);
    let resolver = Arc::new(MockHostnameResolver::new());
    // All IPs resolve to a hostname
    for i in 1..=5 {
        resolver
            .set_response(
                &format!("192.168.1.{}", i + 10),
                Some(&format!("device-{}.local", i)),
            )
            .await;
    }

    let use_case = SyncHostnamesUseCase::new(repo.clone(), resolver.clone());

    // Act - process only 3
    let result = use_case.execute(3).await;

    // Assert - at most 3 resolved
    assert!(result.is_ok());
    assert!(result.unwrap() <= 3);
    assert!(resolver.call_count() <= 3);
}

#[tokio::test]
async fn test_hostname_sync_resolver_error_is_non_fatal() {
    // Arrange - resolver fails for all
    let clients = vec![make_client(1, "192.168.1.100")];
    let repo = Arc::new(MockClientRepository::with_clients(clients).await);
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver.set_should_fail(true).await;

    let use_case = SyncHostnamesUseCase::new(repo, resolver);

    // Act - errors are logged but use case succeeds
    let result = use_case.execute(10).await;

    // Assert - use case doesn't propagate resolver errors
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

// ============================================================================
// Tests: ClientSyncJob construction and scheduling
// ============================================================================

#[tokio::test]
async fn test_client_sync_job_starts_without_panic() {
    // Arrange
    let repo = Arc::new(MockClientRepository::new());
    let arp = Arc::new(MockArpReader::new());
    let resolver = Arc::new(MockHostnameResolver::new());

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp, repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo, resolver));

    let job = Arc::new(ClientSyncJob::new(sync_arp, sync_hostnames));

    // Act - start should not panic
    job.start().await;

    // Give tasks a moment to initialize
    sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn test_client_sync_job_with_custom_intervals() {
    // Arrange - very short intervals so job fires quickly
    let repo = Arc::new(
        MockClientRepository::with_clients(vec![make_client(1, "10.0.0.1")]).await,
    );
    let arp = Arc::new(MockArpReader::with_entries(vec![
        ("10.0.0.1", "de:ad:be:ef:00:01"),
    ]));
    let resolver = Arc::new(MockHostnameResolver::new());
    resolver.set_response("10.0.0.1", Some("router.local")).await;

    let sync_arp = Arc::new(SyncArpCacheUseCase::new(arp.clone(), repo.clone()));
    let sync_hostnames = Arc::new(SyncHostnamesUseCase::new(repo.clone(), resolver.clone()));

    let job = Arc::new(
        ClientSyncJob::new(sync_arp, sync_hostnames).with_intervals(1, 1), // 1 second intervals
    );

    // Act
    job.start().await;

    // Wait for at least one tick
    sleep(Duration::from_millis(1100)).await;

    // Assert - ARP reader was called at least once
    assert!(arp.call_count() >= 1, "ARP sync should have run at least once");
}
