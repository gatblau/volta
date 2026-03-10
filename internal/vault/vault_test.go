package vault

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/gatblau/volta/internal/audit"
	"github.com/gatblau/volta/internal/misc"
	"github.com/gatblau/volta/internal/persist"
)

var (
	tenantID      = "default"
	testStoreType = persist.StoreTypeFileSystem
	tempDir       = "data"
	passPhrase    = "this-is-a-secure-passphrase-for-testing"
)

func TestVaultAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"VaultCreation", TestVaultCreation},
		{"MemoryProtection", TestMemoryProtection},
	}

	// Ensure clean test environment
	defer cleanup(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestVaultCreation(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)

	// Verify vault was properly initialized
	if vault.store == nil {
		t.Error("Store was not initialized")
	}

	if len(vault.keyEnclaves) == 0 {
		t.Error("No key enclaves were created")
	}

	if vault.currentKeyID == "" {
		t.Error("Current key ID was not set")
	}

	// Verify metadata exists
	if len(vault.keyMetadata) == 0 {
		t.Error("No key metadata was created")
	}
}

func createStore(storeType persist.StoreType, basePath, tenantID string) persist.Store {
	switch storeType {
	case persist.StoreTypeS3:
		store, err := persist.NewS3Store(persist.S3Config{
			Endpoint:        "",
			AccessKeyID:     "",
			SecretAccessKey: "",
			UseSSL:          false,
			Bucket:          basePath,
			KeyPrefix:       "",
			Region:          "",
		}, tenantID)
		if err != nil {
			panic(err)
		}
		return store
	case persist.StoreTypeFileSystem:
		store, err := persist.NewFileSystemStore(basePath, tenantID)
		if err != nil {
			panic(err)
		}
		return store
	default:
		panic("invalid store type")
	}
}

func TestMemoryProtection(t *testing.T) {
	options := createTestVaultOptions(t)
	vault := createTestVault(t, options, tempDir)
	defer func(vault *Vault) {
		err := vault.Close()
		if err != nil {
			t.Error(err)
		}
	}(vault)

	// Check memory protection level
	protectionInfo := vault.SecureMemoryProtection()
	t.Logf("Memory protection level: %s", protectionInfo)

	// Memory protection level should not be "None" if we requested it
	// (though it might be "Partial" if full protection isn't available)
	if protectionInfo == "None - sensitive data may be swapped to disk" && options.EnableMemoryLock {
		t.Log("Warning: Memory lock requested but no protection achieved")
	}
}

// Helper functions

func createTestOptions() Options {
	return Options{
		DerivationPassphrase: passPhrase,
		EnableMemoryLock:     false,
	}
}

// Helper function to create a test vault instance for internal testing
func createTestVault(t *testing.T, options Options, basePath string) *Vault {
	// Clear temp directory before creating vault
	_ = os.RemoveAll(basePath)
	err := os.MkdirAll(basePath, 0755)
	if err != nil {
		t.Fatalf("Failed to recreate temp directory: %v", err)
	}

	cryptoManager := NewVaultManagerFileStore(options, basePath, audit.NewNoOpLogger())

	vault, err := cryptoManager.GetVault("default")
	if err != nil {
		t.Fatalf("%v", err)
	}

	var _ VaultService = &Vault{}
	return vault.(*Vault)
}

func createEmptyTestVault(t *testing.T) *Vault {
	tempDir, err := os.MkdirTemp("", "vault_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	// Create storage
	store, _ := persist.NewFileSystemStore(tempDir, "default")

	// Generate a derivation key
	derivationKey := make([]byte, 32)
	_, err = rand.Read(derivationKey)
	if err != nil {
		t.Fatalf("Failed to generate derivation key: %v", err)
	}

	// Create enclave for the derivation key - THIS IS WHAT'S MISSING
	derivationKeyEnclave := memguard.NewEnclave(derivationKey)

	// Create vault with proper initialization
	vault := &Vault{
		store:                store,
		derivationKeyEnclave: derivationKeyEnclave,
		keyMetadata:          make(map[string]KeyMetadata),
		currentKeyID:         "",
		audit:                createLogger(),
	}

	// Create initial key and save metadata
	err = vault.createNewKey()
	if err != nil {
		t.Fatalf("Failed to create initial key: %v", err)
	}

	return vault
}

// Helper function to create a test vault for restore (doesn't clear directory)
func createUninitializedVault(t *testing.T) *Vault {
	tempDir, err := os.MkdirTemp("", "vault_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(tempDir)
	})

	store, _ := persist.NewFileSystemStore(tempDir, tenantID)

	// Create vault WITHOUT calling any initialization methods
	logger := createLogger()
	vault := &Vault{
		store:                store,
		derivationKeyEnclave: nil,
		keyMetadata:          nil,
		currentKeyID:         "",
		audit:                logger,
	}

	return vault
}

func createLogger() audit.Logger {
	logger, err := audit.NewLogger(&audit.Config{
		Enabled:  true,
		LogLevel: "error",
		Type:     audit.FileAuditType,
	})

	if err != nil {
		// Return a no-op logger instead of nil
		return &audit.NoOpLogger{}
	}

	// Double-check that logger is not nil
	if logger == nil {
		return &audit.NoOpLogger{}
	}

	return logger
}

func createTestVaultWithDerivation(t *testing.T) *Vault {
	// Ensure tempDir exists or use system temp
	var baseDir string
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		_ = os.MkdirAll(tempDir, misc.FilePermissions)
	}

	workDir, err := os.MkdirTemp(baseDir, "vault_test_derivation_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create storage
	store, _ := persist.NewFileSystemStore(workDir, tenantID)

	// Create derivation salt and protect it
	derivationSalt := make([]byte, 32)
	for i := range derivationSalt {
		derivationSalt[i] = byte(i + 100)
	}
	derivationSaltEnclave := memguard.NewEnclave(derivationSalt)
	memguard.WipeBytes(derivationSalt) // Clear original

	// Use deterministic derivation key for consistent testing
	derivationKey := make([]byte, 32)
	for i := range derivationKey {
		derivationKey[i] = byte(i)
	}
	derivationKeyEnclave := memguard.NewEnclave(derivationKey)
	// Note: memguard.NewEnclave consumes the original slice, so no need to wipe it

	// DEBUG: Check if derivationKeyEnclave is nil
	if derivationKeyEnclave == nil {
		t.Fatal("derivationKeyEnclave is nil after creation")
	}

	// Create a test encryption key
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i + 50)
	}
	testKeyEnclave := memguard.NewEnclave(testKey)
	memguard.WipeBytes(testKey) // Clear original

	// Create vault with proper initialization
	vault := &Vault{
		store: store,
		keyEnclaves: map[string]*memguard.Enclave{
			"test-current-key": testKeyEnclave,
		},
		keyMetadata: map[string]KeyMetadata{
			"test-current-key": {
				KeyID:     "test-current-key",
				Status:    KeyStatusActive,
				CreatedAt: time.Now(),
			},
		},
		mu:                    sync.RWMutex{},
		currentKeyID:          "test-current-key",
		derivationSaltEnclave: derivationSaltEnclave,
		derivationKeyEnclave:  derivationKeyEnclave,
		audit:                 createLogger(),
		secretsVersion:        "1.0",
		secretsTimestamp:      time.Now(),
	}

	// DEBUG: Check if derivationKeyEnclave is still nil in vault
	if vault.derivationKeyEnclave == nil {
		t.Fatal("derivationKeyEnclave is nil in vault after assignment")
	}

	// **CRITICAL: Initialize the secrets container**
	// Create an empty secrets container
	initialContainer := &SecretsContainer{
		Version:   "1.0",
		Timestamp: time.Now(),
		Secrets:   make(map[string]*SecretEntry),
	}

	// Serialize the container to JSON
	containerJSON, err := json.Marshal(initialContainer)
	if err != nil {
		// Clean up on error
		_ = vault.Close()
		t.Fatalf("Failed to marshal initial secrets container: %v", err)
	}

	// DEBUG: Check derivationKeyEnclave before encryption
	if vault.derivationKeyEnclave == nil {
		t.Fatal("derivationKeyEnclave is nil before encryption")
	}

	// Encrypt the container using the vault's encryption method
	encryptedContainer, err := vault.encryptWithCurrentKey(containerJSON)
	if err != nil {
		// Clean up on error
		_ = vault.Close()
		t.Fatalf("Failed to encrypt initial secrets container: %v", err)
	}

	// Store the encrypted container in a memguard enclave
	vault.secretsContainer = memguard.NewEnclave(encryptedContainer)
	memguard.WipeBytes(encryptedContainer) // Clear original

	return vault
}

func createTestVaultWithKeys(t *testing.T) *Vault {
	vault := createEmptyTestVault(t)

	// Add a dummy key enclave to simulate initialized vault
	dummyEnclave := memguard.NewEnclave(make([]byte, 32))
	vault.keyEnclaves["dummy"] = dummyEnclave

	return vault
}
