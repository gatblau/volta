// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package testutil

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gatblau/volta/internal/audit"
	"github.com/gatblau/volta/pkg"
)

// TestContext holds the state for integration tests
type TestContext struct {
	// Container management
	MinIOContainer *MinIOContainer
	Context        context.Context
	Cancel         context.CancelFunc

	// Vault management
	Manager      pkg.VaultManagerService
	CurrentVault pkg.VaultService
	Tenants      map[string]pkg.VaultService

	// Tenant ID (used for audit logging)
	TenantID string

	// Test state
	LastError    error
	LastErrorMsg string

	// Secret state for step verification
	StoredSecrets    map[string][]byte
	SecretMetadata   map[string]*pkg.SecretMetadata
	SecretsExist     map[string]bool
	SecretsRetrieved map[string]*pkg.SecretResult

	// Key management state
	KeyMetadata   []pkg.KeyMetadata
	ActiveKeyMeta *pkg.KeyMetadata

	// Backup state
	BackupPath string
	Backups    []string

	// Audit state
	AuditLogger  pkg.Logger
	AuditLogPath string
	AuditEvents  []pkg.Event
	AuditSummary *pkg.AuditSummary

	// Encryption state
	LastCiphertext string
	LastPlaintext  []byte

	// Last result for step verification
	LastResult interface{}

	// Multi-tenant state
	ManagerCreated bool

	// Concurrency support
	mu sync.RWMutex
}

// NewTestContext creates a new test context
func NewTestContext() *TestContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &TestContext{
		Context:          ctx,
		Cancel:           cancel,
		Tenants:          make(map[string]pkg.VaultService),
		StoredSecrets:    make(map[string][]byte),
		SecretMetadata:   make(map[string]*pkg.SecretMetadata),
		SecretsExist:     make(map[string]bool),
		SecretsRetrieved: make(map[string]*pkg.SecretResult),
	}
}

// SetupMinIO initializes the MinIO container
func (tc *TestContext) SetupMinIO() error {
	container, err := StartMinIOContainer(tc.Context)
	if err != nil {
		return fmt.Errorf("failed to start MinIO container: %w", err)
	}
	tc.MinIOContainer = container
	return nil
}

// TeardownMinIO stops the MinIO container
func (tc *TestContext) TeardownMinIO() {
	if tc.MinIOContainer != nil {
		_ = tc.MinIOContainer.Stop(tc.Context)
		tc.MinIOContainer = nil
	}
}

// SetupVaultManager initializes a vault manager with S3 backend
// The audit logger is configured later when the tenant is known
func (tc *TestContext) SetupVaultManager() error {
	if tc.MinIOContainer == nil {
		return fmt.Errorf("MinIO container not initialized")
	}

	tenantID := GenerateTenantID()
	config := tc.MinIOContainer.GetS3Config(tenantID)

	options := pkg.Options{
		DerivationPassphrase: GeneratePassphrase(),
		UserID:               "test-user",
	}

	// Create audit logger with the initial tenant ID
	auditDir, err := os.MkdirTemp("", "volta-audit-*")
	if err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}
	tc.AuditLogPath = auditDir

	auditLogPath := fmt.Sprintf("%s/audit.log", auditDir)
	auditConfig := &audit.Config{
		Enabled:  true,
		TenantID: tenantID,
		Type:     audit.FileAuditType,
		Options: map[string]interface{}{
			"file_path":   auditLogPath,
			"max_size":    10,
			"max_backups": 3,
			"max_age":     7,
		},
	}

	auditLogger, err := audit.NewLogger(auditConfig)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}
	tc.AuditLogger = auditLogger
	tc.TenantID = tenantID // Store the tenant ID for reference

	manager, err := pkg.NewVaultManagerS3Store(options, config, auditLogger)
	if err != nil {
		return fmt.Errorf("failed to create vault manager: %w", err)
	}

	tc.Manager = manager
	tc.ManagerCreated = true
	return nil
}

// SetupVaultManagerWithPassphrase initializes a vault manager with a specific passphrase
func (tc *TestContext) SetupVaultManagerWithPassphrase(passphrase string) error {
	if tc.MinIOContainer == nil {
		return fmt.Errorf("MinIO container not initialized")
	}

	tenantID := GenerateTenantID()
	config := tc.MinIOContainer.GetS3Config(tenantID)

	options := pkg.Options{
		DerivationPassphrase: passphrase,
		UserID:               "test-user",
	}

	manager, err := pkg.NewVaultManagerS3Store(options, config, nil)
	if err != nil {
		return fmt.Errorf("failed to create vault manager: %w", err)
	}

	tc.Manager = manager
	tc.ManagerCreated = true
	return nil
}

// GetOrCreateVault gets an existing vault or creates a new one for a tenant
func (tc *TestContext) GetOrCreateVault(tenantID string) (pkg.VaultService, error) {
	tc.mu.RLock()
	if vault, exists := tc.Tenants[tenantID]; exists {
		tc.mu.RUnlock()
		return vault, nil
	}
	tc.mu.RUnlock()

	if tc.Manager == nil {
		return nil, fmt.Errorf("vault manager not initialized")
	}

	vault, err := tc.Manager.GetVault(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault for tenant %s: %w", tenantID, err)
	}

	tc.mu.Lock()
	tc.Tenants[tenantID] = vault
	tc.CurrentVault = vault
	tc.mu.Unlock()

	return vault, nil
}

// SetCurrentVault sets the current vault for operations
func (tc *TestContext) SetCurrentVault(tenantID string) error {
	vault, err := tc.GetOrCreateVault(tenantID)
	if err != nil {
		return err
	}
	tc.CurrentVault = vault
	tc.TenantID = tenantID // Update to match the actual vault tenant
	return nil
}

// StoreSecret stores a secret in the current vault
func (tc *TestContext) StoreSecret(id string, data []byte, tags []string, contentType pkg.ContentType) error {
	if tc.CurrentVault == nil {
		return fmt.Errorf("no current vault set")
	}

	metadata, err := tc.CurrentVault.StoreSecret(id, data, tags, contentType)
	if err != nil {
		tc.LastError = err
		tc.LastErrorMsg = err.Error()
		return err
	}

	tc.mu.Lock()
	tc.StoredSecrets[id] = data
	tc.SecretMetadata[id] = metadata
	tc.mu.Unlock()

	return nil
}

// GetSecret retrieves a secret from the current vault
func (tc *TestContext) GetSecret(id string) (*pkg.SecretResult, error) {
	if tc.CurrentVault == nil {
		return nil, fmt.Errorf("no current vault set")
	}

	result, err := tc.CurrentVault.GetSecret(id)
	if err != nil {
		tc.LastError = err
		tc.LastErrorMsg = err.Error()
		return nil, err
	}

	tc.mu.Lock()
	tc.SecretsRetrieved[id] = result
	tc.mu.Unlock()

	return result, nil
}

// CloseAll closes all vaults and cleans up
func (tc *TestContext) CloseAll() error {
	if tc.Manager != nil {
		if err := tc.Manager.CloseAll(); err != nil {
			return err
		}
		tc.Manager = nil
		tc.CurrentVault = nil
		tc.Tenants = make(map[string]pkg.VaultService)
	}
	return nil
}

// Cleanup removes all test artifacts and closes connections
func (tc *TestContext) Cleanup() {
	_ = tc.CloseAll()
	tc.TeardownMinIO()
	tc.CleanupAuditLogger()
	if tc.Cancel != nil {
		tc.Cancel()
	}
}

// CreateTempBackupDir creates a temporary directory for backups
func (tc *TestContext) CreateTempBackupDir() (string, error) {
	dir, err := os.MkdirTemp("", "volta-backup-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	tc.BackupPath = dir
	return dir, nil
}

// CleanupBackupDir removes the backup directory
func (tc *TestContext) CleanupBackupDir() {
	if tc.BackupPath != "" {
		_ = os.RemoveAll(tc.BackupPath)
		tc.BackupPath = ""
	}
}

// WaitForAsync waits for async operations with timeout
func (tc *TestContext) WaitForAsync(timeout time.Duration, check func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// SetupAuditLogger creates a file-based audit logger for testing
func (tc *TestContext) SetupAuditLogger(tenantID string) error {
	// Create temp directory for audit logs
	auditDir, err := os.MkdirTemp("", "volta-audit-*")
	if err != nil {
		return fmt.Errorf("failed to create audit log directory: %w", err)
	}
	tc.AuditLogPath = auditDir

	// Create audit logger config
	auditLogPath := fmt.Sprintf("%s/audit.log", auditDir)
	auditConfig := &audit.Config{
		Enabled:  true,
		TenantID: tenantID,
		Type:     audit.FileAuditType,
		Options: map[string]interface{}{
			"file_path":   auditLogPath,
			"max_size":    10, // 10MB for tests
			"max_backups": 3,
			"max_age":     7,
		},
	}

	logger, err := audit.NewLogger(auditConfig)
	if err != nil {
		return fmt.Errorf("failed to create audit logger: %w", err)
	}

	tc.AuditLogger = logger
	return nil
}

// QueryAuditLogs queries audit logs with the given options
func (tc *TestContext) QueryAuditLogs(options pkg.QueryOptions) (*pkg.QueryResult, error) {
	if tc.Manager == nil {
		return nil, fmt.Errorf("vault manager not initialized")
	}

	result, err := tc.Manager.QueryAuditLogs(options)
	if err != nil {
		return nil, err
	}

	// Store events for step verification
	tc.AuditEvents = result.Events

	return result, nil
}

// GetAuditEvents returns the captured audit events
func (tc *TestContext) GetAuditEvents() []pkg.Event {
	return tc.AuditEvents
}

// ClearAuditEvents clears the captured audit events
func (tc *TestContext) ClearAuditEvents() {
	tc.AuditEvents = nil
}

// GetAuditSummary retrieves audit summary for a tenant
func (tc *TestContext) GetAuditSummary(tenantID string, since *time.Time) (pkg.AuditSummary, error) {
	if tc.Manager == nil {
		return pkg.AuditSummary{}, fmt.Errorf("vault manager not initialized")
	}

	summary, err := tc.Manager.GetAuditSummary(tenantID, since)
	if err != nil {
		return pkg.AuditSummary{}, err
	}

	tc.AuditSummary = &summary
	return summary, nil
}

// QueryKeyOperations retrieves key operation audit events
func (tc *TestContext) QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]pkg.Event, error) {
	if tc.Manager == nil {
		return nil, fmt.Errorf("vault manager not initialized")
	}

	return tc.Manager.QueryKeyOperations(tenantID, keyID, since)
}

// QuerySecretAccess retrieves secret access audit events
func (tc *TestContext) QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]pkg.Event, error) {
	if tc.Manager == nil {
		return nil, fmt.Errorf("vault manager not initialized")
	}

	return tc.Manager.QuerySecretAccess(tenantID, secretID, since)
}

// CleanupAuditLogger cleans up the audit logger
func (tc *TestContext) CleanupAuditLogger() {
	if tc.AuditLogger != nil {
		_ = tc.AuditLogger.Close()
		tc.AuditLogger = nil
	}

	if tc.AuditLogPath != "" {
		_ = os.RemoveAll(tc.AuditLogPath)
		tc.AuditLogPath = ""
	}
}

// QueryAllTenantsAuditLogs queries audit logs across all tenants
func (tc *TestContext) QueryAllTenantsAuditLogs(options pkg.QueryOptions) (map[string]pkg.QueryResult, error) {
	if tc.Manager == nil {
		return nil, fmt.Errorf("vault manager not initialized")
	}

	return tc.Manager.QueryAllTenantsAuditLogs(options)
}
