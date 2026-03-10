// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gatblau/volta/internal/audit"
	volta "github.com/gatblau/volta/pkg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestBindFlagOrPanicAddsBinding(t *testing.T) {
	flagName := "bind-test"
	rootCmd.PersistentFlags().String(flagName, "", "test")
	bindFlagOrPanic("vault.test.bind_flag", flagName)
	require.NoError(t, rootCmd.PersistentFlags().Set(flagName, "value"))
	require.Equal(t, "value", viper.GetString("vault.test.bind_flag"))
}

func TestSanitizeFlagsMasksSensitiveValues(t *testing.T) {
	cmd := &cobra.Command{Use: "run"}
	cmd.Flags().String("passphrase", "", "")
	cmd.Flags().String("tenant", "", "")
	require.NoError(t, cmd.Flags().Set("passphrase", "secret"))
	require.NoError(t, cmd.Flags().Set("tenant", "ten-123"))

	sanitized := sanitizeFlags(cmd)
	require.Len(t, sanitized, 2)
	require.Equal(t, "[REDACTED]", sanitized["passphrase"])
	require.Equal(t, "ten-123", sanitized["tenant"])
}

func TestCreateAuditLoggerReturnsNoOpWhenDisabled(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("audit.enabled", false)
	logger, err := createAuditLogger()
	require.NoError(t, err)
	require.IsType(t, &audit.NoOpLogger{}, logger)
}

func TestCreateAuditLoggerReturnsErrorForUnknownProvider(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("audit.enabled", true)
	viper.Set("audit.type", "rainbow")
	_, err := createAuditLogger()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown audit provider")
}

func TestCreateVaultManagerRejectsUnsupportedStore(t *testing.T) {
	_, err := createVaultManager("rainbow", volta.Options{}, audit.NewNoOpLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported store type")
}

func TestInitConfigHonorsExplicitConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("vault:\n  store_type: file\n"), 0o600))
	cfgFile = configPath
	viper.Reset()
	initConfig()
	require.Equal(t, "file", viper.GetString("vault.store_type"))
	cfgFile = ""
}

func TestInitializeVaultFailsWithoutPassphrase(t *testing.T) {
	viper.Reset()
	setDefaults()
	viper.Set("vault.path", t.TempDir())
	viper.Set("vault.tenant", "default")
	cmd := &cobra.Command{Use: "run"}
	t.Setenv("VAULT_PASSPHRASE", "")
	err := initializeVault(cmd, []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "vault passphrase is required")
}

func TestInitializeVaultEstablishesManager(t *testing.T) {
	dir := t.TempDir()
	viper.Reset()
	setDefaults()
	viper.Set("vault.path", dir)
	viper.Set("vault.tenant", "default")
	t.Setenv("VAULT_PASSPHRASE", "this-is-a-very-secret")
	cmd := &cobra.Command{Use: "run"}

	err := initializeVault(cmd, []string{})
	require.NoError(t, err)
	require.NotNil(t, vaultManager)
	require.NotNil(t, vaultSvc)
	if vaultSvc != nil {
		require.NoError(t, vaultSvc.Close())
	}
	if vaultManager != nil {
		require.NoError(t, vaultManager.CloseAll())
	}
	passphrase = ""
	vaultManager = nil
	vaultSvc = nil
}
