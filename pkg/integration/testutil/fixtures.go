// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gatblau/volta/pkg"
)

// GenerateRandomID generates a random identifier for testing
func GenerateRandomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateTenantID generates a unique tenant ID for testing
func GenerateTenantID() string {
	return fmt.Sprintf("test-tenant-%d-%s", time.Now().UnixNano(), GenerateRandomID())
}

// GenerateSecretID generates a unique secret ID for testing
func GenerateSecretID(prefix string) string {
	if prefix == "" {
		prefix = "secret"
	}
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixNano(), GenerateRandomID())
}

// GeneratePassphrase generates a random passphrase for testing
func GeneratePassphrase() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateTestOptions creates vault options for testing
func GenerateTestOptions(userID string) pkg.Options {
	return pkg.Options{
		DerivationPassphrase: GeneratePassphrase(),
		UserID:               userID,
	}
}

// GenerateLargeData generates data of specified size for testing
func GenerateLargeData(sizeKB int) []byte {
	data := make([]byte, sizeKB*1024)
	_, _ = rand.Read(data)
	return data
}

// ContentTypeTest represents test data for content type testing
type ContentTypeTest struct {
	SecretID    string
	Content     []byte
	ContentType pkg.ContentType
}

// GetContentTypeTestCases returns test cases for content type testing
func GetContentTypeTestCases() []ContentTypeTest {
	return []ContentTypeTest{
		{
			SecretID:    "config-json",
			Content:     []byte(`{"key":"value","nested":{"item":1}}`),
			ContentType: pkg.ContentTypeJSON,
		},
		{
			SecretID:    "config-yaml",
			Content:     []byte("key: value\nnested:\n  item: 1"),
			ContentType: pkg.ContentTypeYAML,
		},
		{
			SecretID:    "config-toml",
			Content:     []byte("[section]\nkey = \"value\""),
			ContentType: pkg.ContentTypeTOML,
		},
		{
			SecretID:    "config-xml",
			Content:     []byte(`<root><key>value</key></root>`),
			ContentType: pkg.ContentTypeXML,
		},
		{
			SecretID:    "cert-pem",
			Content:     []byte("-----BEGIN CERTIFICATE-----\ntest-data\n-----END CERTIFICATE-----"),
			ContentType: pkg.ContentTypePEM,
		},
		{
			SecretID:    "binary-data",
			Content:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			ContentType: pkg.ContentTypeBinary,
		},
		{
			SecretID:    "text-data",
			Content:     []byte("plain text content for testing"),
			ContentType: pkg.ContentTypeText,
		},
	}
}

// SecretTest represents a secret for testing
type SecretTest struct {
	ID          string
	Data        []byte
	Tags        []string
	ContentType pkg.ContentType
}

// NewSecretTest creates a new test secret
func NewSecretTest(id, data string, tags []string, contentType pkg.ContentType) SecretTest {
	if len(contentType) == 0 {
		contentType = pkg.ContentTypeText
	}
	return SecretTest{
		ID:          id,
		Data:        []byte(data),
		Tags:        tags,
		ContentType: contentType,
	}
}

// DefaultTestSecrets returns a set of default test secrets
func DefaultTestSecrets() []SecretTest {
	return []SecretTest{
		NewSecretTest("db-password", "supersecret123", []string{"env:prod", "type:db"}, pkg.ContentTypeText),
		NewSecretTest("api-key", "api-key-abc-def", []string{"env:prod", "type:api"}, pkg.ContentTypeText),
		NewSecretTest("cert-pem", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", []string{"env:prod", "type:cert"}, pkg.ContentTypePEM),
	}
}
