// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

// Package pkg provides the public API for Volta.
package pkg

import (
	"time"

	"github.com/gatblau/volta/internal/vault"
)

// VaultManagerService provides multi-tenant vault orchestration and administration.
//
// All types used in method signatures (QueryOptions, QueryResult, Event, AuditSummary,
// BulkOperationResult) are defined and accessible from this package, ensuring that
// external consumers never need to import any internal package.
type VaultManagerService interface {
	// GetVault retrieves a VaultService instance for a specific tenant.
	GetVault(tenantID string) (VaultService, error)

	// CloseTenant gracefully shuts down and cleans up resources for a tenant.
	CloseTenant(tenantID string) error

	// CloseAll performs graceful shutdown of all active tenant vaults.
	CloseAll() error

	// ListTenants returns identifiers for all currently active tenants.
	ListTenants() ([]string, error)

	// RotateAllTenantKeys performs encryption key rotation for multiple tenants.
	RotateAllTenantKeys(tenantIDs []string, reason string) ([]BulkOperationResult, error)

	// RotateAllTenantPassphrases updates master passphrases for multiple tenants.
	RotateAllTenantPassphrases(tenantIDs []string, newPassphrase string, reason string) ([]BulkOperationResult, error)

	// QueryAuditLogs performs flexible audit log queries with advanced filtering.
	QueryAuditLogs(options QueryOptions) (*QueryResult, error)

	// GetAuditSummary generates aggregated audit statistics for a tenant.
	GetAuditSummary(tenantID string, since *time.Time) (AuditSummary, error)

	// QueryKeyOperations retrieves audit events for cryptographic key operations.
	QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]Event, error)

	// QuerySecretAccess retrieves audit events for secret access operations.
	QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]Event, error)

	// QueryFailedOperations retrieves audit events for failed operations.
	QueryFailedOperations(tenantID string, since *time.Time) ([]Event, error)

	// QueryPassphraseAccessLogs retrieves audit events for passphrase operations.
	QueryPassphraseAccessLogs(tenantID string, since *time.Time) ([]Event, error)

	// QueryAllTenantsAuditLogs performs cross-tenant audit log queries.
	QueryAllTenantsAuditLogs(options QueryOptions) (map[string]QueryResult, error)

	// QueryTenantAuditLogs performs comprehensive audit queries for a single tenant.
	QueryTenantAuditLogs(tenantID string, options QueryOptions) (QueryResult, error)

	// DeleteTenant securely removes all resources associated with a specified tenant.
	DeleteTenant(tenantID string) error
}

// BulkOperationResult represents the outcome of a bulk operation on a tenant.
type BulkOperationResult = vault.BulkOperationResult

// AuditSummary provides aggregated audit statistics for tenant activity analysis.
type AuditSummary = vault.AuditSummary

// vaultManagerWrapper wraps the internal vault.VaultManagerService to expose a
// clean public API surface with pkg-defined types in all method signatures.
// This ensures external consumers never encounter internal package types.
type vaultManagerWrapper struct {
	inner vault.VaultManagerService
}

func (w *vaultManagerWrapper) GetVault(tenantID string) (VaultService, error) {
	return w.inner.GetVault(tenantID)
}

func (w *vaultManagerWrapper) CloseTenant(tenantID string) error {
	return w.inner.CloseTenant(tenantID)
}

func (w *vaultManagerWrapper) CloseAll() error {
	return w.inner.CloseAll()
}

func (w *vaultManagerWrapper) ListTenants() ([]string, error) {
	return w.inner.ListTenants()
}

func (w *vaultManagerWrapper) RotateAllTenantKeys(tenantIDs []string, reason string) ([]BulkOperationResult, error) {
	return w.inner.RotateAllTenantKeys(tenantIDs, reason)
}

func (w *vaultManagerWrapper) RotateAllTenantPassphrases(tenantIDs []string, newPassphrase string, reason string) ([]BulkOperationResult, error) {
	return w.inner.RotateAllTenantPassphrases(tenantIDs, newPassphrase, reason)
}

func (w *vaultManagerWrapper) QueryAuditLogs(options QueryOptions) (*QueryResult, error) {
	return w.inner.QueryAuditLogs(options)
}

func (w *vaultManagerWrapper) GetAuditSummary(tenantID string, since *time.Time) (AuditSummary, error) {
	return w.inner.GetAuditSummary(tenantID, since)
}

func (w *vaultManagerWrapper) QueryKeyOperations(tenantID string, keyID string, since *time.Time) ([]Event, error) {
	return w.inner.QueryKeyOperations(tenantID, keyID, since)
}

func (w *vaultManagerWrapper) QuerySecretAccess(tenantID string, secretID string, since *time.Time) ([]Event, error) {
	return w.inner.QuerySecretAccess(tenantID, secretID, since)
}

func (w *vaultManagerWrapper) QueryFailedOperations(tenantID string, since *time.Time) ([]Event, error) {
	return w.inner.QueryFailedOperations(tenantID, since)
}

func (w *vaultManagerWrapper) QueryPassphraseAccessLogs(tenantID string, since *time.Time) ([]Event, error) {
	return w.inner.QueryPassphraseAccessLogs(tenantID, since)
}

func (w *vaultManagerWrapper) QueryAllTenantsAuditLogs(options QueryOptions) (map[string]QueryResult, error) {
	return w.inner.QueryAllTenantsAuditLogs(options)
}

func (w *vaultManagerWrapper) QueryTenantAuditLogs(tenantID string, options QueryOptions) (QueryResult, error) {
	return w.inner.QueryTenantAuditLogs(tenantID, options)
}

func (w *vaultManagerWrapper) DeleteTenant(tenantID string) error {
	return w.inner.DeleteTenant(tenantID)
}

// NewVaultManagerFileStore creates a new VaultManager with file system storage.
func NewVaultManagerFileStore(options Options, basePath string, auditLogger Logger) VaultManagerService {
	return &vaultManagerWrapper{inner: vault.NewVaultManagerFileStore(options, basePath, auditLogger)}
}

// NewVaultManagerS3Store creates a new VaultManager with S3 storage.
func NewVaultManagerS3Store(options Options, storeConfig S3Config, auditLogger Logger) (VaultManagerService, error) {
	inner, err := vault.NewVaultManagerS3Store(options, storeConfig, auditLogger)
	if err != nil {
		return nil, err
	}
	return &vaultManagerWrapper{inner: inner}, nil
}

// NewVaultManagerWithStoreFactory creates a new VaultManager with a custom store factory.
func NewVaultManagerWithStoreFactory(options Options, storeFactory func(tenantID string) (Store, error), auditLogger Logger) VaultManagerService {
	return &vaultManagerWrapper{inner: vault.NewVaultManagerWithStoreFactory(options, storeFactory, auditLogger)}
}

// NewVaultManagerWithStoreConfig creates a new VaultManager with store configuration.
func NewVaultManagerWithStoreConfig(options Options, storeConfig StoreConfig, auditLogger Logger) VaultManagerService {
	return &vaultManagerWrapper{inner: vault.NewVaultManagerWithStoreConfig(options, storeConfig, auditLogger)}
}

// NewWithStore creates a new vault instance with the given store.
func NewWithStore(options Options, store Store, auditLogger Logger, tenantID string) (VaultService, error) {
	return vault.NewWithStore(options, store, auditLogger, tenantID)
}
