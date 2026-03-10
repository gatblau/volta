// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

// Package pkg provides the public API for Volta.
package pkg

import (
	"github.com/gatblau/volta/internal/audit"
	"github.com/gatblau/volta/internal/persist"
	"github.com/gatblau/volta/internal/vault"
)

// VaultManagerService provides multi-tenant vault orchestration and administration.
// This is an alias for the internal vault VaultManagerService interface.
type VaultManagerService = vault.VaultManagerService

// BulkOperationResult represents the outcome of a bulk operation on a tenant.
type BulkOperationResult = vault.BulkOperationResult

// AuditSummary provides aggregated audit statistics for tenant activity analysis.
type AuditSummary = vault.AuditSummary

// NewVaultManagerFileStore creates a new VaultManager with file system storage.
func NewVaultManagerFileStore(options Options, basePath string, auditLogger audit.Logger) VaultManagerService {
	return vault.NewVaultManagerFileStore(options, basePath, auditLogger)
}

// NewVaultManagerS3Store creates a new VaultManager with S3 storage.
func NewVaultManagerS3Store(options Options, storeConfig persist.S3Config, auditLogger audit.Logger) (VaultManagerService, error) {
	return vault.NewVaultManagerS3Store(options, storeConfig, auditLogger)
}

// NewVaultManagerWithStoreFactory creates a new VaultManager with a custom store factory.
func NewVaultManagerWithStoreFactory(options Options, storeFactory func(tenantID string) (persist.Store, error), auditLogger audit.Logger) VaultManagerService {
	return vault.NewVaultManagerWithStoreFactory(options, storeFactory, auditLogger)
}

// NewVaultManagerWithStoreConfig creates a new VaultManager with store configuration.
func NewVaultManagerWithStoreConfig(options Options, storeConfig persist.StoreConfig, auditLogger audit.Logger) VaultManagerService {
	return vault.NewVaultManagerWithStoreConfig(options, storeConfig, auditLogger)
}

// NewWithStore creates a new vault instance with the given store.
func NewWithStore(options Options, store persist.Store, auditLogger audit.Logger, tenantID string) (vault.VaultService, error) {
	return vault.NewWithStore(options, store, auditLogger, tenantID)
}
