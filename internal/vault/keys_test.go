package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/gatblau/volta/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeysAll(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"KeyGeneration", TestKeyGeneration},
		{"KeyMetadata", TestKeyMetadata},
		{"KeyRotationMetadata", TestKeyRotationMetadata},
		{"KeyEncryption", TestKeyEncryption},
	}

	// Ensure clean test environment
	defer cleanup(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.fn(t)
		})
	}
}

func TestKeyGeneration(t *testing.T) {
	t.Run("GenerateKeyID", func(t *testing.T) {
		// Test key ID generation
		keyID1 := generateKeyID()
		keyID2 := generateKeyID()

		// Verify format
		assert.NotEmpty(t, keyID1, "Key ID should not be empty")
		assert.NotEmpty(t, keyID2, "Key ID should not be empty")
		assert.Equal(t, 32, len(keyID1), "Key ID should be 32 characters")
		assert.Equal(t, 32, len(keyID2), "Key ID should be 32 characters")

		// Verify uniqueness
		assert.NotEqual(t, keyID1, keyID2, "Generated key IDs should be unique")

		// Verify hexadecimal format
		for _, char := range keyID1 {
			assert.Contains(t, "0123456789abcdef", string(char), "Key ID should be hexadecimal")
		}
	})

	t.Run("GenerateKeyID_Unique", func(t *testing.T) {
		// Generate many key IDs and verify uniqueness
		keyIDs := make(map[string]bool)
		const numKeys = 1000

		for i := 0; i < numKeys; i++ {
			keyID := generateKeyID()
			assert.NotEmpty(t, keyID, "Key ID should not be empty")
			assert.Equal(t, 32, len(keyID), "Key ID should be 32 characters")

			_, exists := keyIDs[keyID]
			assert.False(t, exists, "Key ID should be unique")
			keyIDs[keyID] = true
		}

		assert.Equal(t, numKeys, len(keyIDs), "All generated key IDs should be unique")
	})

	t.Run("GenerateKeyID_ConsistentLength", func(t *testing.T) {
		// Test that all generated key IDs have consistent length
		for i := 0; i < 100; i++ {
			keyID := generateKeyID()
			assert.Equal(t, 32, len(keyID), "Key ID should always be 32 characters")
		}
	})
}

func TestKeyMetadata(t *testing.T) {
	t.Run("KeyMetadata_Creation", func(t *testing.T) {
		keyID := "test-key-id-1234567890123456abcd"
		now := time.Now().UTC()

		metadata := KeyMetadata{
			KeyID:     keyID,
			CreatedAt: now,
			Status:    KeyStatusActive,
			Active:    true,
			Version:   1,
			Reason:    "Test key creation",
		}

		// Verify all fields are set correctly
		assert.Equal(t, keyID, metadata.KeyID)
		assert.Equal(t, now, metadata.CreatedAt)
		assert.Equal(t, KeyStatusActive, metadata.Status)
		assert.True(t, metadata.Active)
		assert.Equal(t, 1, metadata.Version)
		assert.Equal(t, "Test key creation", metadata.Reason)
	})

	t.Run("KeyMetadata_Serialization", func(t *testing.T) {
		keyID := "test-key-id-12345678901234567890123456789012"
		now := time.Now().UTC()
		deactivatedAt := now.Add(time.Hour)

		metadata := KeyMetadata{
			KeyID:         keyID,
			CreatedAt:     now,
			Status:        KeyStatusInactive,
			Active:        false,
			DeactivatedAt: &deactivatedAt,
			Version:       2,
			Reason:        "Test key retirement",
		}

		// Serialize to JSON
		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		// Deserialize from JSON
		var deserialized KeyMetadata
		err = json.Unmarshal(jsonData, &deserialized)
		require.NoError(t, err)

		// Verify all fields are preserved
		assert.Equal(t, metadata.KeyID, deserialized.KeyID)
		assert.Equal(t, metadata.CreatedAt, deserialized.CreatedAt)
		assert.Equal(t, metadata.Status, deserialized.Status)
		assert.Equal(t, metadata.Active, deserialized.Active)
		assert.Equal(t, metadata.Version, deserialized.Version)
		assert.Equal(t, metadata.Reason, deserialized.Reason)

		// Verify DeactivatedAt is preserved
		assert.NotNil(t, deserialized.DeactivatedAt)
		assert.Equal(t, metadata.DeactivatedAt, deserialized.DeactivatedAt)
	})

	t.Run("KeyMetadata_EmptyDeactivatedAt", func(t *testing.T) {
		keyID := "test-key-id-12345678901234567890123456789012"
		now := time.Now().UTC()

		metadata := KeyMetadata{
			KeyID:     keyID,
			CreatedAt: now,
			Status:    KeyStatusActive,
			Active:    true,
			Version:   1,
			Reason:    "Test active key",
		}

		// Serialize to JSON
		jsonData, err := json.Marshal(metadata)
		require.NoError(t, err)

		// Verify DeactivatedAt is omitted from JSON for active keys
		assert.NotContains(t, string(jsonData), "deactivated_at")

		// Deserialize from JSON
		var deserialized KeyMetadata
		err = json.Unmarshal(jsonData, &deserialized)
		require.NoError(t, err)

		// Verify DeactivatedAt is nil for active keys
		assert.Nil(t, deserialized.DeactivatedAt)
	})

	t.Run("KeyMetadata_Validation", func(t *testing.T) {
		keyID := "test-key-id-1234567890123456abcd"
		now := time.Now().UTC()

		metadata := KeyMetadata{
			KeyID:     keyID,
			CreatedAt: now,
			Status:    KeyStatusActive,
			Active:    true,
			Version:   1,
			Reason:    "Test validation",
		}

		// Verify key ID format
		assert.Equal(t, 32, len(metadata.KeyID))
		assert.NotEmpty(t, metadata.KeyID)

		// Verify timestamp is set
		assert.False(t, metadata.CreatedAt.IsZero())

		// Verify status is valid
		assert.True(t, metadata.Status == KeyStatusActive || metadata.Status == KeyStatusInactive)

		// Verify active flag consistency with status
		if metadata.Status == KeyStatusActive {
			assert.True(t, metadata.Active)
		} else {
			assert.False(t, metadata.Active)
		}

		// Verify version is positive
		assert.Greater(t, metadata.Version, 0)

		// Verify reason is not empty
		assert.NotEmpty(t, metadata.Reason)
	})
}

func TestKeyRotationMetadata(t *testing.T) {
	t.Run("KeyRotationMetadata_Creation", func(t *testing.T) {
		keyID := "test-key-id-12345678901234567890123456789012"
		now := time.Now().UTC()

		// Create key metadata
		keyMetadata := KeyMetadata{
			KeyID:     keyID,
			CreatedAt: now,
			Status:    KeyStatusActive,
			Active:    true,
			Version:   1,
			Reason:    "Test key creation",
		}

		// Create encrypted key (simulate encryption)
		encryptedKey := []byte("encrypted-key-data")

		// Create rotation metadata
		rotationMetadata := KeyRotationMetadata{
			Version:       1,
			CurrentKeyID:  keyID,
			LastRotation:  now,
			Keys:          map[string]KeyMetadata{keyID: keyMetadata},
			EncryptedKeys: map[string][]byte{keyID: encryptedKey},
			Reason:        "Test rotation",
		}

		// Verify all fields are set correctly
		assert.Equal(t, 1, rotationMetadata.Version)
		assert.Equal(t, keyID, rotationMetadata.CurrentKeyID)
		assert.Equal(t, now, rotationMetadata.LastRotation)
		assert.Equal(t, 1, len(rotationMetadata.Keys))
		assert.Equal(t, 1, len(rotationMetadata.EncryptedKeys))
		assert.Equal(t, "Test rotation", rotationMetadata.Reason)

		// Verify key metadata is preserved
		assert.Contains(t, rotationMetadata.Keys, keyID)
		assert.Equal(t, keyMetadata, rotationMetadata.Keys[keyID])

		// Verify encrypted key is preserved
		assert.Contains(t, rotationMetadata.EncryptedKeys, keyID)
		assert.Equal(t, encryptedKey, rotationMetadata.EncryptedKeys[keyID])
	})

	t.Run("KeyRotationMetadata_Serialization", func(t *testing.T) {
		keyID1 := "key-id-1-12345678901234567890123456789012"
		keyID2 := "key-id-2-12345678901234567890123456789012"
		now := time.Now().UTC()

		// Create key metadata
		keyMetadata1 := KeyMetadata{
			KeyID:     keyID1,
			CreatedAt: now,
			Status:    KeyStatusActive,
			Active:    true,
			Version:   1,
			Reason:    "Test key 1",
		}

		keyMetadata2 := KeyMetadata{
			KeyID:         keyID2,
			CreatedAt:     now.Add(-time.Hour),
			Status:        KeyStatusInactive,
			Active:        false,
			DeactivatedAt: &now,
			Version:       1,
			Reason:        "Test key 2",
		}

		// Create encrypted keys
		encryptedKey1 := []byte("encrypted-key-1-data")
		encryptedKey2 := []byte("encrypted-key-2-data")

		// Create rotation metadata
		rotationMetadata := KeyRotationMetadata{
			Version:       2,
			CurrentKeyID:  keyID1,
			LastRotation:  now,
			Keys:          map[string]KeyMetadata{keyID1: keyMetadata1, keyID2: keyMetadata2},
			EncryptedKeys: map[string][]byte{keyID1: encryptedKey1, keyID2: encryptedKey2},
			Reason:        "Test rotation with multiple keys",
		}

		// Serialize to JSON
		jsonData, err := json.Marshal(rotationMetadata)
		require.NoError(t, err)

		// Deserialize from JSON
		var deserialized KeyRotationMetadata
		err = json.Unmarshal(jsonData, &deserialized)
		require.NoError(t, err)

		// Verify all fields are preserved
		assert.Equal(t, rotationMetadata.Version, deserialized.Version)
		assert.Equal(t, rotationMetadata.CurrentKeyID, deserialized.CurrentKeyID)
		assert.Equal(t, rotationMetadata.LastRotation, deserialized.LastRotation)
		assert.Equal(t, rotationMetadata.Reason, deserialized.Reason)

		// Verify keys map is preserved
		assert.Equal(t, len(rotationMetadata.Keys), len(deserialized.Keys))
		assert.Contains(t, deserialized.Keys, keyID1)
		assert.Contains(t, deserialized.Keys, keyID2)
		assert.Equal(t, rotationMetadata.Keys[keyID1], deserialized.Keys[keyID1])
		assert.Equal(t, rotationMetadata.Keys[keyID2], deserialized.Keys[keyID2])

		// Verify encrypted keys map is preserved
		assert.Equal(t, len(rotationMetadata.EncryptedKeys), len(deserialized.EncryptedKeys))
		assert.Contains(t, deserialized.EncryptedKeys, keyID1)
		assert.Contains(t, deserialized.EncryptedKeys, keyID2)
		assert.Equal(t, rotationMetadata.EncryptedKeys[keyID1], deserialized.EncryptedKeys[keyID1])
		assert.Equal(t, rotationMetadata.EncryptedKeys[keyID2], deserialized.EncryptedKeys[keyID2])
	})

	t.Run("KeyRotationMetadata_Validation", func(t *testing.T) {
		keyID := "test-key-id-12345678901234567890123456789012"
		now := time.Now().UTC()

		keyMetadata := KeyMetadata{
			KeyID:     keyID,
			CreatedAt: now,
			Status:    KeyStatusActive,
			Active:    true,
			Version:   1,
			Reason:    "Test validation",
		}

		rotationMetadata := KeyRotationMetadata{
			Version:       1,
			CurrentKeyID:  keyID,
			LastRotation:  now,
			Keys:          map[string]KeyMetadata{keyID: keyMetadata},
			EncryptedKeys: map[string][]byte{keyID: []byte("encrypted-key")},
			Reason:        "Test validation",
		}

		// Verify version is positive
		assert.Greater(t, rotationMetadata.Version, 0)

		// Verify current key ID is not empty
		assert.NotEmpty(t, rotationMetadata.CurrentKeyID)

		// Verify last rotation timestamp is set
		assert.False(t, rotationMetadata.LastRotation.IsZero())

		// Verify keys map is not empty
		assert.NotEmpty(t, rotationMetadata.Keys)

		// Verify encrypted keys map is not empty
		assert.NotEmpty(t, rotationMetadata.EncryptedKeys)

		// Verify current key exists in both maps
		assert.Contains(t, rotationMetadata.Keys, rotationMetadata.CurrentKeyID)
		assert.Contains(t, rotationMetadata.EncryptedKeys, rotationMetadata.CurrentKeyID)

		// Verify reason is not empty
		assert.NotEmpty(t, rotationMetadata.Reason)
	})
}

func TestKeyEncryption(t *testing.T) {
	t.Run("KeyEncryption_Decryption", func(t *testing.T) {
		// Generate a test key
		testKey := make([]byte, 32)
		_, err := rand.Read(testKey)
		require.NoError(t, err)

		// Generate a derivation key
		derivationKey := make([]byte, 32)
		_, err = rand.Read(derivationKey)
		require.NoError(t, err)

		// Encrypt the key
		encryptedKey, err := crypto.EncryptValue(testKey, derivationKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedKey)
		assert.NotEqual(t, testKey, encryptedKey)

		// Decrypt the key
		decryptedKey, err := crypto.DecryptValue(encryptedKey, derivationKey)
		require.NoError(t, err)
		assert.Equal(t, testKey, decryptedKey)

		// Verify original key is unchanged
		assert.Equal(t, testKey, decryptedKey)

		// Clean up
		memguard.WipeBytes(testKey)
		memguard.WipeBytes(derivationKey)
		memguard.WipeBytes(decryptedKey)
	})

	t.Run("KeyEncryption_WeakKeyDetection", func(t *testing.T) {
		// Test with weak key patterns
		weakKeys := [][]byte{
			// All zeros
			make([]byte, 32),
			// All ones
			bytes.Repeat([]byte{0xFF}, 32),
			// Sequential bytes
			{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
			// Repeated pattern
			bytes.Repeat([]byte{0x12, 0x34, 0x56, 0x78}, 8),
		}

		derivationKey := make([]byte, 32)
		_, err := rand.Read(derivationKey)
		require.NoError(t, err)

		for i, weakKey := range weakKeys {
			t.Run(fmt.Sprintf("WeakKey_%d", i), func(t *testing.T) {
				// Test that weak keys are detected
				assert.True(t, crypto.IsWeakKey(weakKey), "Should detect weak key pattern")

				// Test encryption still works (but key is weak)
				encryptedKey, err := crypto.EncryptValue(weakKey, derivationKey)
				require.NoError(t, err)
				assert.NotEmpty(t, encryptedKey)

				// Test decryption works
				decryptedKey, err := crypto.DecryptValue(encryptedKey, derivationKey)
				require.NoError(t, err)
				assert.Equal(t, weakKey, decryptedKey)

				// Clean up
				memguard.WipeBytes(decryptedKey)
			})
		}

		// Clean up
		memguard.WipeBytes(derivationKey)
	})

	t.Run("KeyEncryption_StrongKey", func(t *testing.T) {
		// Generate a strong random key
		strongKey := make([]byte, 32)
		_, err := rand.Read(strongKey)
		require.NoError(t, err)

		// Test that strong key is not detected as weak
		assert.False(t, crypto.IsWeakKey(strongKey), "Should not detect strong key as weak")

		// Test encryption and decryption
		derivationKey := make([]byte, 32)
		_, err = rand.Read(derivationKey)
		require.NoError(t, err)

		encryptedKey, err := crypto.EncryptValue(strongKey, derivationKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encryptedKey)

		decryptedKey, err := crypto.DecryptValue(encryptedKey, derivationKey)
		require.NoError(t, err)
		assert.Equal(t, strongKey, decryptedKey)

		// Clean up
		memguard.WipeBytes(strongKey)
		memguard.WipeBytes(derivationKey)
		memguard.WipeBytes(decryptedKey)
	})

	t.Run("KeyEncryption_EnclaveIntegration", func(t *testing.T) {
		// Generate test key
		testKey := make([]byte, 32)
		_, err := rand.Read(testKey)
		require.NoError(t, err)

		// Keep a copy of the original key so we can compare after memguard zeroes the input
		expectedKey := make([]byte, len(testKey))
		copy(expectedKey, testKey)

		// Create enclave with test key
		keyEnclave := memguard.NewEnclave(testKey)

		// Get key from enclave
		keyView, err := keyEnclave.Open()
		require.NoError(t, err)

		// Verify key content
		assert.Equal(t, expectedKey, keyView.Bytes())

		// Clean up
		keyView.Destroy()
		memguard.WipeBytes(testKey)
	})
}

// Helper functions

func cleanup(t *testing.T) {
	// Clean up any test directories that might be lingering
	tempBase := os.TempDir()
	entries, err := os.ReadDir(tempBase)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() &&
				(strings.HasPrefix(entry.Name(), "vault_test_") ||
					strings.HasPrefix(entry.Name(), "test_vault_")) {
				fullPath := filepath.Join(tempBase, entry.Name())
				if err := os.RemoveAll(fullPath); err != nil {
					t.Logf("Warning: failed to clean up temp dir %s: %v", fullPath, err)
				}
			}
		}
	}
}
