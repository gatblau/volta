Feature: Multi-Tenant Vault Management
  As a platform operator
  I want to manage multiple isolated tenant vaults
  So that different applications have separate secret stores

  Background:
    Given a vault manager with S3 backend is initialized

  Scenario: Complete tenant isolation
    Given I create a vault for tenant "tenant-prod"
    And I create a vault for tenant "tenant-staging"
    When I store a secret "db-password" with "prod-password" in tenant "tenant-prod"
    And I store a secret "db-password" with "staging-password" in tenant "tenant-staging"
    Then tenant "tenant-prod" should have secret "db-password" with value "prod-password"
    And tenant "tenant-staging" should have secret "db-password" with value "staging-password"

  Scenario: Tenant data isolation verification
    Given I create a vault for tenant "isolation-a"
    And I create a vault for tenant "isolation-b"
    When I store a secret "private-key" with "key-a" in tenant "isolation-a"
    And I store a secret "private-key" with "key-b" in tenant "isolation-b"
    Then secret "private-key" in tenant "isolation-a" should not equal secret "private-key" in tenant "isolation-b"

  Scenario: Concurrent tenant operations
    Given I create vaults for tenants "concurrent-1,concurrent-2,concurrent-3,concurrent-4,concurrent-5"
    When I concurrently store secrets in all tenants
    Then all operations should succeed
    And all secrets should be retrievable

  Scenario: Tenant enumeration
    Given I create vaults for tenants "enum-a,enum-b,enum-c"
    When I list all tenants
    Then I should see exactly 3 tenants
    And the list should be sorted alphabetically

  Scenario: Resource cleanup on tenant deletion
    Given I create a vault for tenant "cleanup-test"
    And I store 5 secrets in tenant "cleanup-test"
    When I delete tenant "cleanup-test"
    Then no S3 objects should remain for tenant "cleanup-test"
    And the tenant should not be listable

  Scenario: Tenant-specific key rotation
    Given I create a vault for tenant "key-rotation-tenant"
    And I store a secret "test-secret" containing "original-data" in tenant "key-rotation-tenant"
    When I rotate the data encryption key with reason "tenant-specific-rotation" in tenant "key-rotation-tenant"
    Then the key rotation should succeed in tenant "key-rotation-tenant"
    And secret "test-secret" should still be accessible in tenant "key-rotation-tenant"

  Scenario: Cross-tenant secret isolation
    Given I create a vault for tenant "cross-tenant-a"
    And I create a vault for tenant "cross-tenant-b"
    And I store a secret "shared-id" with "value-a" in tenant "cross-tenant-a"
    When I retrieve secret "shared-id" from tenant "cross-tenant-b"
    Then the operation should fail with secret not found error