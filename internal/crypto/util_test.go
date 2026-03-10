// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/awnumar/memguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCalculateChecksum tests the CalculateChecksum function
func TestCalculateChecksum(t *testing.T) {
	// Test with empty data
	checksum := CalculateChecksum([]byte{})
	assert.NotEmpty(t, checksum)
	assert.Len(t, checksum, 64, "SHA-256 produces 64 hex characters")

	// Test with specific data
	data := []byte("hello world")
	checksum1 := CalculateChecksum(data)
	checksum2 := CalculateChecksum(data)
	assert.Equal(t, checksum1, checksum2, "same data should produce same checksum")

	// Test that different data produces different checksums
	checksum3 := CalculateChecksum([]byte("different data"))
	assert.NotEqual(t, checksum1, checksum3, "different data should produce different checksum")
}

// TestEncryptValue tests the EncryptValue function
func TestEncryptValue(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	value := []byte("secret message")

	encrypted, err := EncryptValue(value, key)
	require.NoError(t, err)
	assert.NotEqual(t, value, encrypted, "encrypted data should differ from original")

	// Should have nonce prefix
	assert.Greater(t, len(encrypted), len(value), "encrypted data should be larger than original")
}

// TestDecryptValue tests the DecryptValue function
func TestDecryptValue(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	original := []byte("secret message")

	// First encrypt
	encrypted, err := EncryptValue(original, key)
	require.NoError(t, err)

	// Then decrypt
	decrypted, err := DecryptValue(encrypted, key)
	require.NoError(t, err)
	assert.Equal(t, original, decrypted, "decrypted data should match original")
}

// TestDecryptValueWithWrongKey tests that decryption fails with wrong key
func TestDecryptValueWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
	}

	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(31 - i)
	}

	original := []byte("secret message")

	encrypted, err := EncryptValue(original, key1)
	require.NoError(t, err)

	// Decrypting with wrong key should fail
	_, err = DecryptValue(encrypted, key2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

// TestDecryptValueWithTooShortData tests that decryption fails with too short data
func TestDecryptValueWithTooShortData(t *testing.T) {
	key := make([]byte, 32)

	// Empty data
	_, err := DecryptValue([]byte{}, key)
	assert.Error(t, err)

	// Too short for nonce
	_, err = DecryptValue([]byte{1, 2, 3}, key)
	assert.Error(t, err)
}

// TestIsWeakKey tests the IsWeakKey function
func TestIsWeakKey(t *testing.T) {
	// Too short
	assert.True(t, IsWeakKey([]byte("short")))

	// All zeros
	allZeros := make([]byte, 32)
	assert.True(t, IsWeakKey(allZeros))

	// All same byte
	allSame := make([]byte, 32)
	for i := range allSame {
		allSame[i] = 0xAA
	}
	assert.True(t, IsWeakKey(allSame))

	// Low entropy (only a few unique bytes)
	lowEntropy := make([]byte, 32)
	for i := range lowEntropy {
		lowEntropy[i] = byte(i % 4)
	}
	assert.True(t, IsWeakKey(lowEntropy))

	// Strong key (random-looking)
	strongKey := make([]byte, 32)
	for i := range strongKey {
		strongKey[i] = byte((i * 7) % 256)
	}
	assert.False(t, IsWeakKey(strongKey), "key with good entropy should not be considered weak")

	// Sequential pattern should be considered weak
	sequential := make([]byte, 32)
	for i := range sequential {
		sequential[i] = byte(i)
	}
	assert.True(t, IsWeakKey(sequential), "sequential pattern should be weak")

	// Repeating sub-pattern should be considered weak
	repeating := make([]byte, 32)
	for i := range repeating {
		repeating[i] = byte(i % 2)
	}
	assert.True(t, IsWeakKey(repeating), "repeating pattern should be weak")
}

// TestEncryptDecryptRoundTrip tests a full encrypt/decrypt cycle
func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	original := []byte("The quick brown fox jumps over the lazy dog")

	encrypted, err := EncryptValue(original, key)
	require.NoError(t, err)

	decrypted, err := DecryptValue(encrypted, key)
	require.NoError(t, err)

	assert.Equal(t, original, decrypted)
}

// TestEncryptWithPassphrase verifies passphrase encryption path
func TestEncryptWithPassphrase(t *testing.T) {
	data := []byte("sensitive data")
	passphrase := "p@ssword!"

	encrypted, err := EncryptWithPassphrase(data, passphrase)
	require.NoError(t, err)

	decrypted, err := DecryptWithPassphrase(encrypted, passphrase)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)

	_, err = DecryptWithPassphrase([]byte{0x01}, passphrase)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted data too short")

	_, err = DecryptWithPassphrase(encrypted, "wrong")
	assert.Error(t, err)
}

// TestDeriveKey ensures key derivation with a real enclave salt
func TestDeriveKey(t *testing.T) {
	saltBytes := make([]byte, 32)
	_, err := rand.Read(saltBytes)
	require.NoError(t, err)
	defer memguard.WipeBytes(saltBytes)

	password := []byte("vault-passphrase")
	enclave := memguard.NewEnclave(saltBytes)
	derived, err := DeriveKey(password, enclave)
	require.NoError(t, err)
	defer derived.Destroy()
	assert.GreaterOrEqual(t, derived.Size(), 32)
}
