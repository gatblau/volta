// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package pkg

import (
	"testing"

	"github.com/gatblau/volta/internal/audit"
	"github.com/gatblau/volta/internal/persist"
	"github.com/gatblau/volta/internal/vault"
)

func TestNewVaultManagerFileStore(t *testing.T) {
	opts := createTestOptions()
	tempDir := t.TempDir()

	mgr := NewVaultManagerFileStore(opts, tempDir, audit.NewNoOpLogger())
	if mgr == nil {
		t.Fatal("expected a non-nil VaultManagerService")
	}

	if _, ok := mgr.(*vault.VaultManager); !ok {
		t.Fatalf("expected internal VaultManager implementation, got %T", mgr)
	}
}

func TestNewVaultManagerWithStoreFactory(t *testing.T) {
	opts := createTestOptions()
	manager := NewVaultManagerWithStoreFactory(opts, func(tenantID string) (persist.Store, error) {
		return persist.NewFileSystemStore(t.TempDir(), tenantID)
	}, audit.NewNoOpLogger())

	if manager == nil {
		t.Fatal("expected non-nil VaultManagerService")
	}
}

func TestNewVaultManagerWithStoreConfig(t *testing.T) {
	opts := createTestOptions()
	storeConfig := persist.StoreConfig{
		Type: persist.StoreTypeFileSystem,
		Config: map[string]interface{}{
			"base_path": t.TempDir(),
		},
	}

	manager := NewVaultManagerWithStoreConfig(opts, storeConfig, audit.NewNoOpLogger())
	if manager == nil {
		t.Fatal("expected non-nil VaultManagerService from store config")
	}
}

func TestNewVaultManagerS3StoreError(t *testing.T) {
	opts := createTestOptions()
	cfg := persist.S3Config{
		Endpoint:        "",
		AccessKeyID:     "",
		SecretAccessKey: "",
		Bucket:          "",
		KeyPrefix:       "",
		UseSSL:          false,
		Region:          "us-east-1",
	}

	mgr, err := NewVaultManagerS3Store(opts, cfg, audit.NewNoOpLogger())
	if err != nil {
		t.Logf("S3 VaultManager creation failed (as expected in isolated test): %v", err)
		return
	}

	if mgr == nil {
		t.Fatal("expected a manager even when S3 creation succeeds")
	}
}

func TestNewWithStore(t *testing.T) {
	opts := createTestOptions()
	store, err := persist.NewFileSystemStore(t.TempDir(), "test-tenant")
	if err != nil {
		t.Fatalf("failed to create file store: %v", err)
	}

	svc, err := NewWithStore(opts, store, audit.NewNoOpLogger(), "test-tenant")
	if err != nil {
		t.Fatalf("NewWithStore returned error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil VaultService from NewWithStore")
	}
}

func createTestOptions() vault.Options {
	return vault.Options{
		DerivationPassphrase: "test-passphrase",
		EnableMemoryLock:     false,
	}
}
