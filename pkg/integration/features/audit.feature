Feature: Audit Logging
  As a compliance officer
  I want comprehensive audit logging
  So that I can track all vault operations for security and compliance

  Background:
    Given a vault manager with S3 backend is initialized
    And a vault for tenant "audit-test" is created
    And audit logging is enabled

  Scenario: Secret access audit trail
    Given I store a secret "audited-secret" containing "sensitive-data"
    When I retrieve the secret "audited-secret"
    Then an audit event should be logged for "SecretAccess"
    And the event should contain the secret ID "audited-secret"
    And the event should contain the action "GET_SECRET"

  Scenario: Key operation audit trail
    When I rotate the data encryption key with reason "audit test"
    Then an audit event should be logged for "KeyOperation"
    And the event should contain the action "ROTATE_START"
    And the event should contain the action "ROTATE_SUCCESS"

  Scenario: Failed operation audit trail
    When I attempt to retrieve nonexistent secret "nonexistent-secret"
    Then an audit event should be logged for "FailedOperation"
    And the event should contain the error message

  Scenario: Query audit logs
    Given I perform 5 secret operations
    When I query audit logs for the last hour
    Then I should receive at least 5 events
    And each event should have a timestamp
    And each event should have an operation type

  Scenario: Audit summary
    Given I perform various operations in the last hour
    When I get the audit summary for the last hour
    Then I should receive operation counts by type
    And I should see the total operation count

  Scenario: Query key operations
    Given I rotate the data encryption key twice
    When I query key operations for the last hour
    Then I should see 2 key rotation events

  Scenario: Query secret access events
    Given I store a secret "query-test" containing "data"
    And I retrieve the secret "query-test" 3 times
    When I query secret access for "query-test"
    Then I should see at least 3 access events

  Scenario: Cross-tenant audit query
    Given I create a vault for tenant "audit-tenant-1"
    And I create a vault for tenant "audit-tenant-2"
    And I perform operations in both tenants
    When I query audit logs across all tenants
    Then I should see events from both tenants
    And events should be properly isolated by tenant