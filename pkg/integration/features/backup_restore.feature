Feature: Backup and Restore Operations
  As a vault administrator
  I want to backup and restore vault data
  So that I can recover from data loss or migrate vaults

  Background:
    Given a vault manager with S3 backend is initialized
    And a vault for tenant "backup-test" is created

  Scenario: Full backup and restore cycle
    Given I store secrets "db-password", "api-key", "cert-pem" with random data
    When I create a backup with passphrase "backup-passphrase"
    Then the backup should be created successfully
    When I close the vault
    And I restore from the latest backup with passphrase "backup-passphrase"
    Then all secrets should be accessible
    And the key metadata should be preserved

  Scenario: Backup with key rotation
    Given I store a secret "old-secret" containing "old-data"
    When I rotate the data encryption key with reason "scheduled rotation"
    And I store a secret "new-secret" containing "new-data"
    And I create a backup with passphrase "rotation-backup"
    Then the backup should contain both keys
    When I restore from backup with passphrase "rotation-backup"
    Then secret "old-secret" should be accessible
    And secret "new-secret" should be accessible

  Scenario: Multiple backups management
    Given I store a secret "backup-1-secret" containing "data-1"
    When I create a backup with ID "backup-1" and passphrase "pass-1"
    And I store a secret "backup-2-secret" containing "data-2"
    And I create a backup with ID "backup-2" and passphrase "pass-2"
    When I list all backups
    Then I should see 2 backups
    When I restore from backup "backup-1" with passphrase "pass-1"
    Then secret "backup-1-secret" should be accessible
    And secret "backup-2-secret" should not exist

  Scenario: Restore with wrong passphrase
    Given I create a backup with passphrase "correct-passphrase"
    When I restore from backup with passphrase "wrong-passphrase"
    Then the restore should fail with authentication error

  Scenario: Cross-tenant backup restore
    Given I create a vault for tenant "source-tenant"
    And I store a secret "migrate-secret" containing "migrate-data" in tenant "source-tenant"
    And I create a backup with passphrase "migrate-pass"
    When I create a vault for tenant "dest-tenant"
    And I restore from backup to tenant "dest-tenant" with passphrase "migrate-pass"
    Then tenant "dest-tenant" should have secret "migrate-secret" with value "migrate-data"

  Scenario: Backup integrity verification
    Given I store a secret "integrity-test" containing "test-data"
    When I create a backup with passphrase "integrity-pass"
    Then the backup file should be valid
    And the backup should contain encrypted data