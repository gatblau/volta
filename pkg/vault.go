// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package pkg

import (
	"context"
	"time"
)

// VaultService defines the public interface for interacting with the vault.
//
// The vault manages its primary keys internally and ensures they are not directly exportable.
// It uses these keys to encrypt and decrypt provided data while maintaining strict
// separation between key material and application data.
//
// Key Design Principles:
//   - Zero-trust: Keys are never exposed outside the vault instance
//   - Fail-secure: Operations fail safely when keys are unavailable
//   - Audit-first: All operations are logged for compliance and security monitoring
//   - Memory-safe: Sensitive data is cleared from memory when no longer needed
//
// Thread Safety:
// Implementations of VaultService should be thread-safe for concurrent access,
// though individual operations may acquire locks as needed for consistency.
//
// Error Handling:
// All operations return errors that provide sufficient detail for troubleshooting
// while avoiding information disclosure that could aid attackers.
type VaultService interface {

	// === Core Cryptographic Operations ===

	// Encrypt encrypts plaintext data using the current active key.
	Encrypt(plaintext []byte) (ciphertextWithKeyID string, err error)

	// Decrypt decrypts data that was previously encrypted by this vault instance.
	Decrypt(base64CiphertextWithKeyID string) (plaintext []byte, err error)

	// === Key Management Operations ===

	// RotateDataEncryptionKey generates a new data encryption key (DEK), makes it the active key for
	// new encryptions, and deactivates the previously active key.
	RotateDataEncryptionKey(reason string) (*KeyMetadata, error)

	// DestroyKey permanently removes an inactive key and its material from the vault.
	DestroyKey(keyID string) error

	// === Backup and Recovery Operations ===

	// Backup creates an encrypted backup of all non-decommissioned keys,
	// their operational metadata, and the vault's derivation salt to the
	// specified destination directory.
	Backup(destinationDir, passphrase string) error

	// Restore recovers vault state from a previously created backup.
	Restore(destinationDir, passphrase string) error

	// === Key Metadata and Status Operations ===

	// ListKeyMetadata returns metadata for all known keys managed by the vault.
	ListKeyMetadata() ([]KeyMetadata, error)

	// GetActiveKeyMetadata returns the metadata for the key currently
	// active for encryption operations.
	GetActiveKeyMetadata() (KeyMetadata, error)

	// === Secret CRUD Operations ===

	// StoreSecret encrypts and stores secret data with optional metadata.
	StoreSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)

	// GetSecret retrieves a secret by its ID.
	GetSecret(secretID string) (*SecretResult, error)

	// UpdateSecret updates existing secret data and increments the version number.
	UpdateSecret(secretID string, secretData []byte, tags []string, contentType ContentType) (*SecretMetadata, error)

	// DeleteSecret removes a secret and its metadata from the vault.
	DeleteSecret(secretID string) error

	// SecretExists checks if a secret exists without retrieving its data.
	SecretExists(secretID string) (bool, error)

	// ListSecrets returns secret metadata based on filter options.
	ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error)

	// GetSecretMetadata returns only the metadata for a secret without decrypting the data.
	GetSecretMetadata(secretID string) (*SecretMetadata, error)

	// === System Operations ===

	// Close securely wipes all sensitive key material from the vault's memory
	// and releases associated resources.
	Close() error

	// =============================================================================
	// VAULT SECURE SECRET ACCESS INTERFACE
	// =============================================================================

	// UseSecret executes a function with a secret and ensures automatic cleanup.
	UseSecret(secretID string, fn func(data []byte) error) error

	// UseSecretWithTimeout executes a function with a secret with automatic timeout.
	UseSecretWithTimeout(secretID string, timeout time.Duration, fn func(data []byte) error) error

	// UseSecretWithContext executes a function with a secret using a custom context.
	UseSecretWithContext(ctx context.Context, secretID string, fn func(data []byte) error) error

	// UseSecretString executes a function with a secret as a string and ensures cleanup.
	UseSecretString(secretID string, fn func(secret string) error) error

	// GetSecretWithTimeout retrieves a secret with automatic timeout-based cleanup.
	GetSecretWithTimeout(secretID string, timeout time.Duration) (*SecretWithContext, error)

	// GetSecretWithContext retrieves a secret with custom context-based cleanup.
	GetSecretWithContext(ctx context.Context, secretID string) (*SecretWithContext, error)

	// =============================================================================
	// MULTI-SECRET INTERFACE METHODS - Secure handling of multiple secrets
	// =============================================================================

	// UseSecrets provides secure access to multiple secrets within a single callback.
	UseSecrets(secretIDs []string, fn func(secrets map[string][]byte) error) error

	// UseSecretsString provides secure access to multiple secrets as UTF-8 strings.
	UseSecretsString(secretIDs []string, fn func(secrets map[string]string) error) error

	// UseSecretPair provides secure access to exactly two secrets with ergonomic API.
	UseSecretPair(secretID1, secretID2 string, fn func(secret1, secret2 []byte) error) error

	// UseSecretPairString provides secure access to exactly two secrets as UTF-8 strings.
	UseSecretPairString(secretID1, secretID2 string, fn func(secret1, secret2 string) error) error

	// SecureMemoryProtection returns information about the memory protection
	// mechanisms currently active for this vault instance.
	SecureMemoryProtection() string

	// RotateKeyEncryptionKey changes the vault's master passphrase used for key derivation.
	RotateKeyEncryptionKey(newPassphrase string, reason string) error

	// GetAudit returns the audit logger instance used by this vault.
	GetAudit() Logger

	// DeleteTenant securely removes all resources associated with a specified tenant.
	DeleteTenant(tenantID string) error
}
