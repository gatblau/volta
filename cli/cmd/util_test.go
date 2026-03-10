// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestIsSensitiveFlag tests the isSensitiveFlag function
func TestIsSensitiveFlag(t *testing.T) {
	// Test sensitive flag names
	assert.True(t, isSensitiveFlag("passphrase"))
	assert.True(t, isSensitiveFlag("password"))
	assert.True(t, isSensitiveFlag("secret"))
	assert.True(t, isSensitiveFlag("key"))
	assert.True(t, isSensitiveFlag("token"))

	// Test case insensitivity
	assert.True(t, isSensitiveFlag("PASSPHRASE"))
	assert.True(t, isSensitiveFlag("PASSWORD"))

	// Test non-sensitive flag names
	assert.False(t, isSensitiveFlag("tenant"))
	assert.False(t, isSensitiveFlag("path"))
	assert.False(t, isSensitiveFlag("verbose"))
}

// TestFormatError tests the formatError function
func TestFormatError(t *testing.T) {
	// Test with nil error
	result := formatError(nil)
	assert.Equal(t, "", result)

	// Test with simple error
	err := errors.New("simple error")
	result = formatError(err)
	assert.Equal(t, "Error: Simple error", result)

	// Test with wrapped error (simulated)

	// Test that error message is capitalized
	err = errors.New("starts with lowercase")
	result = formatError(err)
	assert.Equal(t, "Error: Starts with lowercase", result)
}

// TestSanitizeArgs tests the sanitizeArgs function
func TestSanitizeArgs(t *testing.T) {
	// Test with empty args
	result := sanitizeArgs([]string{})
	assert.Empty(t, result)

	// Test with normal args
	args := []string{"arg1", "arg2"}
	result = sanitizeArgs(args)
	assert.Equal(t, args, result)

	// Test that currently all args pass through
	// (containsSensitiveData always returns false per the implementation)
	argsWithSensitive := []string{"normal", "--passphrase=secret"}
	result = sanitizeArgs(argsWithSensitive)
	assert.Equal(t, argsWithSensitive, result)
}

func TestConvertStringValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  interface{}
	}{
		{name: "bool true", input: "true", want: true},
		{name: "bool false", input: "false", want: false},
		{name: "integer", input: "42", want: 42},
		{name: "float", input: "3.14", want: 3.14},
		{name: "string", input: "hello", want: "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertStringValue(tt.input)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUnsetNestedKey(t *testing.T) {
	config := map[string]interface{}{
		"vault": map[string]interface{}{
			"s3": map[string]interface{}{
				"bucket": "test",
			},
		},
	}

	err := unsetNestedKey(config, "vault.s3.bucket")
	assert.NoError(t, err)

	vaultSection, ok := config["vault"].(map[string]interface{})
	assert.True(t, ok)
	s3Section, ok := vaultSection["s3"].(map[string]interface{})
	assert.True(t, ok)
	_, exists := s3Section["bucket"]
	assert.False(t, exists)

	err = unsetNestedKey(config, "vault.s3.bucket")
	assert.Error(t, err)
}

func TestEnsureConfigDir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nested", "config.yaml")

	assert.NoError(t, ensureConfigDir(configPath))

	info, err := os.Stat(filepath.Dir(configPath))
	assert.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestGetConfigTemplate(t *testing.T) {
	cases := []struct {
		name     string
		template string
	}{
		{name: "default", template: "default"},
		{name: "minimal", template: "minimal"},
		{name: "full", template: "full"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := getConfigTemplate(tt.template)
			_, vaultExists := tmpl["vault"].(map[string]interface{})
			assert.True(t, vaultExists)
		})
	}
}

func TestValidateConfiguration(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		setDefaults()
	})

	t.Run("invalid store type", func(t *testing.T) {
		viper.Reset()
		setDefaults()
		viper.Set("vault.store_type", "unknown")

		errors := validateConfiguration()
		assert.Len(t, errors, 1)
		assert.Contains(t, errors[0], "invalid store type")
	})

	t.Run("s3 missing bucket", func(t *testing.T) {
		viper.Reset()
		setDefaults()
		viper.Set("vault.store_type", "s3")
		viper.Set("vault.s3.region", "us-east-1")

		errors := validateConfiguration()
		assert.Len(t, errors, 1)
		assert.Contains(t, errors[0], "S3 bucket is required")
	})

	t.Run("audit invalid type", func(t *testing.T) {
		viper.Reset()
		setDefaults()
		viper.Set("audit.enabled", true)
		viper.Set("audit.type", "potato")

		errors := validateConfiguration()
		assert.Len(t, errors, 1)
		assert.Contains(t, errors[0], "invalid audit type")
	})

	t.Run("valid configuration", func(t *testing.T) {
		viper.Reset()
		setDefaults()
		viper.Set("vault.store_type", "file")
		viper.Set("audit.enabled", false)

		errors := validateConfiguration()
		assert.Empty(t, errors)
	})
}

func TestMaskSensitiveValues(t *testing.T) {
	config := map[string]interface{}{
		"vault": map[string]interface{}{
			"passphrase": "secret",
		},
		"audit": map[string]interface{}{
			"options": map[string]interface{}{
				"file_path": "audit.log",
			},
		},
	}

	maskSensitiveValues(config)
	vaultSection := config["vault"].(map[string]interface{})
	assert.Equal(t, "[REDACTED]", vaultSection["passphrase"])
}
