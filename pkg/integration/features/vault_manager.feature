Feature: Vault Manager Service
  As a platform operator
  I want to manage vault instances for multiple tenants
  So that different applications have isolated secret stores

  Background:
    Given a vault manager with S3 backend is initialized

  Scenario: Create vault for new tenant
    When I create a vault for tenant "new-tenant"
    Then the vault should be accessible
    And the tenant "new-tenant" should appear in the tenant list

  Scenario: Get existing vault
    Given I create a vault for tenant "existing-tenant"
    When I get the vault for tenant "existing-tenant"
    Then I should receive a valid VaultService

  Scenario: List all tenants
    Given I create vaults for tenants "tenant-a,tenant-b,tenant-c"
    When I list all tenants
    Then the result should contain "tenant-a", "tenant-b", "tenant-c"

  Scenario: Close tenant
    Given I create a vault for tenant "to-close"
    And I store a secret with ID "test-secret" containing "data" in tenant "to-close"
    When I close tenant "to-close"
    Then the tenant should be inactive
    When I get the vault for tenant "to-close"
    Then a new vault instance should be created

  Scenario: Close all tenants
    Given I create vaults for tenants "close-a,close-b,close-c"
    When I close all tenants
    Then all tenants should be inactive

  Scenario: Delete tenant
    Given I create a vault for tenant "to-delete"
    And I store a secret with ID "test-secret" containing "data" in tenant "to-delete"
    When I delete tenant "to-delete"
    Then tenant "to-delete" should not exist
    When I list all tenants
    Then the result should not contain "to-delete"

  Scenario: Create vault manager with S3 store
    Given S3 backend is running
    When I create a vault manager with S3 configuration
    Then the vault manager should be initialized
    And the connection to S3 should be valid

  Scenario: Bulk key rotation for multiple tenants
    Given I create vaults for tenants "bulk-a,bulk-b,bulk-c"
    And I store a secret with ID "test" containing "data" in each tenant
    When I rotate keys for tenants "bulk-a,bulk-b,bulk-c" with reason "scheduled rotation"
    Then all key rotations should succeed
    And all secrets should still be accessible