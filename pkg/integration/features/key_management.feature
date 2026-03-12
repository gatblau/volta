Feature: Key Management Operations
  As a security administrator
  I want to manage encryption keys
  So that I can maintain security through key rotation

  Background:
    Given a vault manager with S3 backend is initialized
    And a vault for tenant "key-test" is created

  Scenario: DEK rotation
    Given I store a secret "pre-rotation" containing "data"
    When I rotate the data encryption key with reason "monthly Rotation"
    Then a new key should be active
    And the previous key should be inactive
    And secret "pre-rotation" should still be accessible
    When I store a secret "post-rotation" containing "new-data"
    Then secret "post-rotation" should be encrypted with the new key

  Scenario: Key listing
    Given I rotate the data encryption key 3 times
    When I list all key metadata
    Then I should see 4 keys
    And exactly 1 key should be active
    And 3 keys should be inactive

  Scenario: Key destruction
    Given I rotate the data encryption key
    And I rotate the data encryption key again
    When I list all key metadata
    Then I should have inactive keys
    When I destroy the oldest inactive key
    Then the key should no longer exist
    And secrets encrypted with destroyed key should not be accessible

  Scenario: KEK rotation
    Given I store a secret "kek-test" containing "data"
    When I rotate the key encryption key to "new-passphrase" with reason "security policy"
    Then the operation should succeed
    And secret "kek-test" should still be accessible
    When I close and reopen the vault with passphrase "new-passphrase"
    Then secret "kek-test" should be accessible

  Scenario: Get active key metadata
    Given I have an active key
    When I get the active key metadata
    Then I should receive valid key metadata
    And the key status should be "Active"
    And the key ID should not be empty

  Scenario: Key rotation with multiple secrets
    Given I store secrets "secret-1", "secret-2", "secret-3" with random data
    When I rotate the data encryption key with reason "security rotation"
    Then all existing secrets should remain accessible
    And new secrets should use the new key

  Scenario: Key rotation audit trail
    Given I rotate the data encryption key with reason "audit test"
    When I query key operations for the last hour
    Then I should see a key rotation event
    And the event should contain the reason "audit test"