# Volta Integration Tests

This directory contains comprehensive integration tests for the Volta vault service using BDD (Behavior-Driven Development) with Cucumber/Gherkin-style specifications.

## Overview

The integration tests verify:

1. **VaultService Operations** - Core secret CRUD, encryption/decryption, key management
2. **VaultManagerService Operations** - Multi-tenant management, bulk operations
3. **Multi-Tenant Isolation** - Complete tenant data isolation
4. **Backup and Restore** - Data persistence and recovery workflows
5. **Key Management** - DEK rotation, KEK rotation, key destruction
6. **Audit Logging** - Comprehensive audit trail for all operations

## Architecture

```
pkg/integration/
├── features/                      # Gherkin feature files
│   ├── vault_service.feature      # VaultService scenarios
│   ├── vault_manager.feature      # VaultManagerService scenarios
│   ├── multi_tenant.feature       # Multi-tenant scenarios
│   ├── backup_restore.feature     # Backup/restore workflows
│   ├── key_management.feature     # Key rotation scenarios
│   └── audit.feature              # Audit logging scenarios
├── step_definitions/              # Go step implementations
│   └── common_steps.go             # Shared step definitions
├── testutil/
│   ├── container.go               # Testcontainers MinIO setup
│   ├── fixtures.go                # Test fixtures and helpers
│   └── context.go                 # Test context management
├── integration_test.go            # Test suite entry point
└── README.md                      # This file
```

## Prerequisites

- Docker (for testcontainers)
- Go 1.25+

## Running Tests

### Run All Integration Tests

```bash
go test -v ./pkg/integration/...
```

### Run Specific Feature

```bash
go test -v ./pkg/integration/... -run TestFeatures/VaultService
```

### Run with Coverage

```bash
go test -v -coverprofile=coverage.out ./pkg/integration/...
go tool cover -html=coverage.out
```

### Run with godog CLI

```bash
cd pkg/integration
godog run ./features/
```

## Test Categories

### 1. Vault Service Feature (`vault_service.feature`)

Tests the core vault operations:

- Store and retrieve secrets
- Update existing secrets
- Delete secrets
- Check secret existence
- Store secrets with tags
- Encrypt and decrypt data
- Large secret data handling
- List secrets with pagination
- Secret content types
- Secret metadata retrieval

### 2. Vault Manager Feature (`vault_manager.feature`)

Tests multi-tenant vault management:

- Create vault for new tenant
- Get existing vault
- List all tenants
- Close tenant
- Close all tenants
- Delete tenant
- Bulk key rotation

### 3. Multi-Tenant Feature (`multi_tenant.feature`)

Tests tenant isolation:

- Complete tenant isolation
- Tenant data isolation verification
- Concurrent tenant operations
- Tenant enumeration
- Resource cleanup on tenant deletion
- Cross-tenant secret isolation

### 4. Backup/Restore Feature (`backup_restore.feature`)

Tests data persistence:

- Full backup and restore cycle
- Backup with key rotation
- Multiple backups management
- Restore with wrong passphrase
- Cross-tenant backup restore

### 5. Key Management Feature (`key_management.feature`)

Tests cryptographic key operations:

- DEK rotation
- Key listing
- Key destruction
- KEK rotation
- Get active key metadata
- Key rotation with multiple secrets
- Key rotation audit trail

### 6. Audit Feature (`audit.feature`)

Tests audit logging:

- Secret access audit trail
- Key operation audit trail
- Failed operation audit trail
- Query audit logs
- Audit summary
- Cross-tenant audit query

## Writing New Tests

### Adding a New Feature File

Create a `.feature` file in the `features/` directory:

```gherkin
Feature: New Feature Name
  As a user
  I want to perform some action
  So that I achieve some goal

  Background:
    Given a vault manager with S3 backend is initialized
    And a vault for tenant "test-tenant" is created

  Scenario: First scenario
    Given some precondition
    When some action
    Then some result
```

### Adding New Step Definitions

Add step methods to `step_definitions/common_steps.go`:

```go
func (tc *TestContext) iPerformSomeAction(arg string) error {
    // Implementation
    return nil
}
```

Register the step in `InitializeCommonSteps`:

```go
sc.Step(`^I perform some action "([^"]*)"$`, tc.iPerformSomeAction)
```

## Test Context

The `TestContext` in `testutil/context.go` manages:

- MinIO testcontainer lifecycle
- Vault manager and vault instances
- Secret state tracking
- Key metadata
- Audit events

## Test Utilities

### container.go

Provides MinIO testcontainer setup for S3-compatible storage testing.

### fixtures.go

Provides test data generation:

- Random ID generation
- Tenant ID generation
- Passphrase generation
- Large data generation
- Content type test cases

### context.go

Manages test state:

- Vault manager setup
- Secret storage and retrieval
- Vault lifecycle management
- Cleanup operations

## Coverage Goals

| Package | Current | Target |
|---------|---------|--------|
| `pkg/vault.go` | ~30% | ~85% |
| `pkg/vault_manager.go` | ~25% | ~80% |
| `pkg/store.go` | ~40% | ~90% |
| `pkg/audit.go` | ~20% | ~75% |
| **Overall `pkg/`** | ~30% | ~80% |

## Troubleshooting

### Docker Not Running

If tests fail with container errors, ensure Docker is running:

```bash
docker ps
```

### Port Conflicts

If port 9000 is in use, testcontainers will use a random port. If issues persist:

```bash
# Kill processes using port 9000
lsof -i :9000 | grep LISTEN | awk '{print $2}' | xargs kill
```

### Cleanup Issues

To force cleanup of testcontainers:

```bash
docker ps -a | grep minio | awk '{print $1}' | xargs docker rm -f
```

## CI/CD Integration

For CI/CD pipelines, ensure:

1. Docker is available in the runner
2. Sufficient timeouts for container startup
3. Proper cleanup on test failure

Example GitHub Actions workflow:

```yaml
name: Integration Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Run integration tests
        run: go test -v -timeout 30m ./pkg/integration/...
```

## License

Apache-2.0 - See LICENSE file for details.