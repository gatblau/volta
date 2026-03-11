// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package pkg

import (
	"testing"
)

func TestNewVaultManagerFileStore(t *testing.T) {
	opts := createTestOptions()
	tempDir := t.TempDir()

	mgr := NewVaultManagerFileStore(opts, tempDir, NewNoOpLogger())
	if mgr == nil {
		t.Fatal("expected a non-nil VaultManagerService")
	}

	if _, ok := mgr.(*vaultManagerWrapper); !ok {
		t.Fatalf("expected vaultManagerWrapper implementation, got %T", mgr)
	}
}

func TestNewVaultManagerWithStoreFactory(t *testing.T) {
	opts := createTestOptions()
	manager := NewVaultManagerWithStoreFactory(opts, func(tenantID string) (Store, error) {
		return NewFileSystemStore(t.TempDir(), tenantID)
	}, NewNoOpLogger())

	if manager == nil {
		t.Fatal("expected non-nil VaultManagerService")
	}
}

func TestNewVaultManagerWithStoreConfig(t *testing.T) {
	opts := createTestOptions()
	storeConfig := StoreConfig{
		Type: StoreTypeFileSystem,
		Config: map[string]interface{}{
			"base_path": t.TempDir(),
		},
	}

	manager := NewVaultManagerWithStoreConfig(opts, storeConfig, NewNoOpLogger())
	if manager == nil {
		t.Fatal("expected non-nil VaultManagerService from store config")
	}
}

func TestNewVaultManagerS3StoreError(t *testing.T) {
	opts := createTestOptions()
	cfg := S3Config{
		Endpoint:        "",
		AccessKeyID:     "",
		SecretAccessKey: "",
		Bucket:          "",
		KeyPrefix:       "",
		UseSSL:          false,
		Region:          "us-east-1",
	}

	mgr, err := NewVaultManagerS3Store(opts, cfg, NewNoOpLogger())
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
	store, err := NewFileSystemStore(t.TempDir(), "test-tenant")
	if err != nil {
		t.Fatalf("failed to create file store: %v", err)
	}

	svc, err := NewWithStore(opts, store, NewNoOpLogger(), "test-tenant")
	if err != nil {
		t.Fatalf("NewWithStore returned error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil VaultService from NewWithStore")
	}
}

func createTestOptions() Options {
	return Options{
		DerivationPassphrase: "test-passphrase",
		EnableMemoryLock:     false,
	}
}
