// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOptionsValidate tests the Validate method of Options
func TestOptionsValidate(t *testing.T) {
	// Test with both passphrase and env var - should be valid
	opts := Options{
		DerivationPassphrase: "test-passphrase",
		EnvPassphraseVar:     "TEST_VAR",
	}
	err := opts.Validate()
	assert.NoError(t, err, "should be valid with both passphrase and env var")

	// Test with only passphrase - should be valid
	opts = Options{
		DerivationPassphrase: "test-passphrase",
		EnvPassphraseVar:     "",
	}
	err = opts.Validate()
	assert.NoError(t, err, "should be valid with only passphrase")

	// Test with only env var - should be valid
	opts = Options{
		DerivationPassphrase: "",
		EnvPassphraseVar:     "TEST_VAR",
	}
	err = opts.Validate()
	assert.NoError(t, err, "should be valid with only env var")

	// Test with neither - should be invalid
	opts = Options{
		DerivationPassphrase: "",
		EnvPassphraseVar:     "",
	}
	err = opts.Validate()
	assert.Error(t, err, "should be invalid with neither passphrase nor env var")
	assert.Contains(t, err.Error(), "either DerivationPassphrase or EnvPassphraseVar must be provided")
}

// TestKeyStatusConstants tests that KeyStatus constants are defined correctly
func TestKeyStatusConstants(t *testing.T) {
	assert.Equal(t, KeyStatus("active"), KeyStatusActive)
	assert.Equal(t, KeyStatus("inactive"), KeyStatusInactive)
}

// TestCryptoAlgorithmConstants tests that CryptoAlgorithm constants are defined correctly
func TestCryptoAlgorithmConstants(t *testing.T) {
	assert.Equal(t, CryptoAlgorithm("chacha20poly1305"), ChaCha20Poly1305)
}

// TestContentTypeConstants tests that ContentType constants are defined correctly
func TestContentTypeConstants(t *testing.T) {
	assert.Equal(t, ContentType("text/plain"), ContentTypeText)
	assert.Equal(t, ContentType("application/json"), ContentTypeJSON)
	assert.Equal(t, ContentType("application/toml"), ContentTypeTOML)
	assert.Equal(t, ContentType("application/xml"), ContentTypeXML)
	assert.Equal(t, ContentType("application/yaml"), ContentTypeYAML)
	assert.Equal(t, ContentType("application/x-pem-file"), ContentTypePEM)
	assert.Equal(t, ContentType("application/octet-stream"), ContentTypeBinary)
}

// TestSecretResultFields tests that SecretResult has correct fields
func TestSecretResultFields(t *testing.T) {
	result := SecretResult{
		Data:          []byte("secret data"),
		Metadata:      nil,
		UsedActiveKey: true,
	}

	assert.Equal(t, []byte("secret data"), result.Data)
	assert.True(t, result.UsedActiveKey)
}

// TestSecretListOptionsFields tests that SecretListOptions has correct fields
func TestSecretListOptionsFields(t *testing.T) {
	opts := SecretListOptions{
		Tags:        []string{"tag1", "tag2"},
		Prefix:      "secret/",
		Limit:       10,
		Offset:      5,
		ContentType: ContentTypeJSON,
	}

	assert.Equal(t, []string{"tag1", "tag2"}, opts.Tags)
	assert.Equal(t, "secret/", opts.Prefix)
	assert.Equal(t, 10, opts.Limit)
	assert.Equal(t, 5, opts.Offset)
	assert.Equal(t, ContentTypeJSON, opts.ContentType)
}
