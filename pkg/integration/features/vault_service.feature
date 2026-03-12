Feature: Vault Service Operations
  As a security-conscious application developer
  I want to securely store and retrieve secrets
  So that my application can access sensitive data safely

  Background:
    Given a vault manager with S3 backend is initialized
    And a vault for tenant "test-tenant" is created

  Scenario: Store and retrieve a secret
    Given I store a secret with ID "db-password" containing "supersecret123"
    When I retrieve the secret with ID "db-password"
    Then the secret data should equal "supersecret123"
    And the secret metadata should show version 1

  Scenario: Update an existing secret
    Given I store a secret with ID "api-key" containing "old-key"
    When I update the secret with ID "api-key" to contain "new-key"
    Then I retrieve the secret with ID "api-key"
    Then the secret data should equal "new-key"
    And the secret metadata should show version 2

  Scenario: Delete a secret
    Given I store a secret with ID "to-delete" containing "data"
    When I delete the secret with ID "to-delete"
    Then the secret with ID "to-delete" should not exist

  Scenario: Check secret existence
    Given I store a secret with ID "existing-secret" containing "data"
    When I check if secret "existing-secret" exists
    Then the result should be true
    When I check if secret "nonexistent-secret" exists
    Then the result should be false

  Scenario: Store secret with tags
    Given I store a secret with ID "tagged-secret" containing "data" with tags "env:prod,type:db"
    When I list secrets with tags "env:prod"
    Then the list should contain "tagged-secret"
    When I list secrets with tags "type:db"
    Then the list should contain "tagged-secret"
    When I list secrets with tags "env:staging"
    Then the list should not contain "tagged-secret"

  Scenario: Encrypt and decrypt data
    Given I have plaintext data "sensitive information"
    When I encrypt the plaintext
    Then I should receive ciphertext with a key ID
    When I decrypt the ciphertext
    Then the result should equal "sensitive information"

  Scenario: Large secret data handling
    Given I store a secret with ID "large-secret" containing 1MB of data
    When I retrieve the secret with ID "large-secret"
    Then the data should be intact
    And the size should be 1MB

  Scenario: List secrets with pagination
    Given I store 10 secrets with prefix "list-test/"
    When I list secrets with prefix "list-test/"
    Then I should receive all 10 secrets
    And each secret should have metadata

  Scenario: Secret with different content types
    Given I store a secret with ID "json-secret" containing '{"key":"value"}' as JSON content type
    When I retrieve the secret with ID "json-secret"
    Then the content type should be "JSON"

  Scenario: Get secret metadata without data
    Given I store a secret with ID "metadata-test" containing "secret-data"
    When I get secret metadata for ID "metadata-test"
    Then the metadata should contain correct information
    And the secret ID should be "metadata-test"
    And the size should match the data size

  Scenario Outline: Store secrets with different content types
    Given I store a secret with ID "<secret-id>" containing <content> as <content-type> content type
    When I retrieve the secret with ID "<secret-id>"
    Then the content type should be "<content-type>"
    And the data should be intact

    Examples:
      | secret-id     | content                    | content-type |
      | config-json   | {"key":"value"}            | JSON         |
      | config-yaml   | key: value                 | YAML         |
      | config-toml   | [section]\nkey=value       | TOML         |
      | config-xml    | <root><key/></root>        | XML          |
      | cert-pem      | -----BEGIN CERT...         | PEM          |
      | binary-data   | \x00\x01\x02               | Binary       |
      | text-data     | plain text                 | Text         |