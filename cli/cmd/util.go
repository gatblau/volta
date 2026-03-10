// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func getConfigFilePath(global bool) string {
	if global {
		// System-wide config (e.g., /etc/vault/config.yaml)
		return "/etc/vault/config.yaml"
	}

	if cfgFile != "" {
		return cfgFile
	}

	// User config
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vault.yaml")
}

func ensureConfigDir(configFile string) error {
	dir := filepath.Dir(configFile)
	return os.MkdirAll(dir, 0700)
}

func isValidConfigKey(key string) bool {
	validKeys := []string{
		"vault.store_type",
		"vault.path",
		"vault.passphrase",
		"vault.tenant",
		"vault.file.path",
		"vault.s3.bucket",
		"vault.s3.region",
		"vault.s3.prefix",
		"vault.redis.address",
		"vault.redis.db",
		"vault.redis.password",
		"audit.enabled",
		"audit.type",
		"audit.options.file_path",
		"audit.verbose",
	}

	for _, validKey := range validKeys {
		if key == validKey {
			return true
		}
	}
	return false
}

func convertStringValue(value string) (interface{}, error) {
	// Try to convert to appropriate type
	if value == "true" || value == "false" {
		return value == "true", nil
	}

	// Try integer
	if strings.Contains(value, ".") {
		// Try float
		if f, err := parseFloat(value); err == nil {
			return f, nil
		}
	} else {
		// Try integer
		if i, err := parseInt(value); err == nil {
			return i, nil
		}
	}

	// Return as string
	return value, nil
}

func unsetNestedKey(config map[string]interface{}, key string) error {
	parts := strings.Split(key, ".")

	// Navigate to parent
	current := config
	for i, part := range parts[:len(parts)-1] {
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return fmt.Errorf("key path not found at %s", strings.Join(parts[:i+1], "."))
		}
	}

	finalKey := parts[len(parts)-1]
	if _, exists := current[finalKey]; !exists {
		return fmt.Errorf("key path not found at %s", key)
	}

	delete(current, finalKey)
	return nil
}

func getConfigTemplate(template string) map[string]interface{} {
	switch template {
	case "minimal":
		return map[string]interface{}{
			"vault": map[string]interface{}{
				"store_type": "file",
				"path":       ".vault",
				"tenant":     "default",
			},
		}
	case "full":
		return map[string]interface{}{
			"vault": map[string]interface{}{
				"store_type": "file",
				"path":       ".vault",
				"tenant":     "default",
				"file": map[string]interface{}{
					"path": ".vault",
				},
				"s3": map[string]interface{}{
					"bucket": "",
					"region": "us-east-1",
					"prefix": "vault/",
				},
				"redis": map[string]interface{}{
					"address":  "localhost:6379",
					"db":       0,
					"password": "",
				},
			},
			"audit": map[string]interface{}{
				"enabled": false,
				"type":    "file",
				"options": map[string]interface{}{
					"file_path": "audit.log",
				},
				"verbose": false,
			},
		}
	default: // "default"
		return map[string]interface{}{
			"vault": map[string]interface{}{
				"store_type": "file",
				"path":       ".vault",
				"tenant":     "default",
			},
			"audit": map[string]interface{}{
				"enabled": false,
				"type":    "file",
				"options": map[string]interface{}{
					"file_path": "audit.log",
				},
			},
		}
	}
}

func validateConfiguration() []string {
	var errors []string

	// Validate store type
	storeType := viper.GetString("vault.store_type")
	validStoreTypes := []string{"file", "memory", "s3", "redis"}
	if !contains(validStoreTypes, storeType) {
		errors = append(errors, fmt.Sprintf("invalid store type: %s (must be one of: %s)",
			storeType, strings.Join(validStoreTypes, ", ")))
	}

	// Store-specific validation
	switch storeType {
	case "s3":
		if bucket := viper.GetString("vault.s3.bucket"); bucket == "" {
			errors = append(errors, "S3 bucket is required when using S3 store")
		}
	case "redis":
		if addr := viper.GetString("vault.redis.address"); addr == "" {
			errors = append(errors, "Redis address is required when using Redis store")
		}
	}

	// Validate audit configuration
	if viper.GetBool("audit.enabled") {
		auditType := viper.GetString("audit.type")
		validAuditTypes := []string{"file", "syslog"}
		if !contains(validAuditTypes, auditType) {
			errors = append(errors, fmt.Sprintf("invalid audit type: %s (must be one of: %s)",
				auditType, strings.Join(validAuditTypes, ", ")))
		}

		if auditType == "file" {
			if filePath := viper.GetString("audit.options.file_path"); filePath == "" {
				errors = append(errors, "audit file path is required when using file audit")
			}
		}
	}

	return errors
}

func getConfigKeyDescriptions() map[string]string {
	return map[string]string{
		"vault.store_type":        "Storage backend type (file, memory, s3, redis)",
		"vault.path":              "Path to vault storage (for file store)",
		"vault.passphrase":        "Vault passphrase for encryption",
		"vault.tenant":            "Tenant identifier",
		"vault.file.path":         "File store path",
		"vault.s3.bucket":         "S3 bucket name",
		"vault.s3.region":         "S3 region",
		"vault.s3.prefix":         "S3 key prefix",
		"vault.redis.address":     "Redis server address",
		"vault.redis.db":          "Redis database number",
		"vault.redis.password":    "Redis password",
		"audit.enabled":           "Enable audit logging",
		"audit.type":              "Audit logger type (file, syslog)",
		"audit.options.file_path": "Audit log file path",
		"audit.verbose":           "Enable verbose audit logging",
	}
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// parseInt attempts to parse a string as an integer
func parseInt(s string) (int, error) {
	return strconv.Atoi(s)
}

// parseFloat attempts to parse a string as a float64
func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// printConfigTable prints configuration in table format
func printConfigTable() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() { _ = w.Flush() }()

	_, _ = fmt.Fprintln(w, "KEY\tVALUE\tSOURCE")
	_, _ = fmt.Fprintln(w, "---\t-----\t------")

	// Get all settings
	settings := viper.AllSettings()
	var keys []string

	// Flatten nested keys
	flattenKeys(settings, "", &keys)
	sort.Strings(keys)

	for _, key := range keys {
		value := viper.Get(key)
		source := "default"
		if viper.ConfigFileUsed() != "" {
			source = filepath.Base(viper.ConfigFileUsed())
		}

		// Check if this is an environment variable
		envKey := strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		if os.Getenv(envKey) != "" || os.Getenv("VAULT_"+envKey) != "" {
			source = "environment"
		}

		// Mask sensitive values
		if isSensitiveConfigKey(key) {
			value = "[REDACTED]"
		}

		_, _ = fmt.Fprintf(w, "%s\t%v\t%s\n", key, value, source)
	}

	return nil
}

// printConfigJSON prints configuration in JSON format
func printConfigJSON() error {
	config := viper.AllSettings()

	// Mask sensitive values
	maskSensitiveValues(config)

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// printConfigYAML prints configuration in YAML format
func printConfigYAML() error {
	config := viper.AllSettings()

	// Mask sensitive values
	maskSensitiveValues(config)

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config to YAML: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

// printConfigKeysTable prints available configuration keys in table format
func printConfigKeysTable(keys map[string]string) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() { _ = w.Flush() }()

	_, _ = fmt.Fprintln(w, "KEY\tDESCRIPTION")
	_, _ = fmt.Fprintln(w, "---\t-----------")

	// Sort keys
	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		_, _ = fmt.Fprintf(w, "%s\t%s\n", key, keys[key])
	}

	return nil
}

// printConfigKeysYAML prints available configuration keys in YAML format
func printConfigKeysYAML(keys map[string]string) error {
	data, err := yaml.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to marshal keys to YAML: %w", err)
	}

	fmt.Print(string(data))
	return nil
}

// printConfigKeysJSON prints available configuration keys in JSON format
func printConfigKeysJSON(keys map[string]string) error {
	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// flattenKeys recursively flattens nested maps into dot-notation keys
func flattenKeys(m map[string]interface{}, prefix string, keys *[]string) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		if nested, ok := v.(map[string]interface{}); ok {
			flattenKeys(nested, key, keys)
		} else {
			*keys = append(*keys, key)
		}
	}
}

// isSensitiveConfigKey checks if a configuration key contains sensitive data
func isSensitiveConfigKey(key string) bool {
	sensitiveKeys := []string{"passphrase", "password", "secret", "key", "token", "auth"}
	lowerKey := strings.ToLower(key)

	for _, sensitive := range sensitiveKeys {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}
	return false
}

// maskSensitiveValues recursively masks sensitive values in configuration
func maskSensitiveValues(config map[string]interface{}) {
	for key, value := range config {
		if isSensitiveConfigKey(key) {
			config[key] = "[REDACTED]"
		} else if nested, ok := value.(map[string]interface{}); ok {
			maskSensitiveValues(nested)
		}
	}
}

// getDefaultEditor returns the default text editor for the current platform
func getDefaultEditor() string {
	// First check EDITOR environment variable
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}

	// Check VISUAL environment variable
	if visual := os.Getenv("VISUAL"); visual != "" {
		return visual
	}

	// Platform-specific defaults
	switch runtime.GOOS {
	case "windows":
		// Try common Windows editors
		editors := []string{"notepad++.exe", "notepad.exe", "code.exe"}
		for _, editor := range editors {
			if _, err := exec.LookPath(editor); err == nil {
				return editor
			}
		}
		return "notepad.exe"
	case "darwin":
		// Try common macOS editors
		editors := []string{"code", "nano", "vim", "vi"}
		for _, editor := range editors {
			if _, err := exec.LookPath(editor); err == nil {
				return editor
			}
		}
		return "nano"
	default:
		// Try common Unix/Linux editors
		editors := []string{"nano", "vim", "vi", "emacs", "code"}
		for _, editor := range editors {
			if _, err := exec.LookPath(editor); err == nil {
				return editor
			}
		}
		return "vi" // ultimate fallback
	}
}

// executeEditor launches the specified editor with the given file.
//
// Security hardening (G204 / shell-injection):
//   - The editor string is tokenised with strings.Fields so that a value such as
//     "emacs -nw" (common in $EDITOR) is split into binary + args correctly,
//     rather than being passed as a single path that would silently fail.
//   - The binary token is resolved through exec.LookPath to confirm it exists on
//     PATH and to obtain the absolute, clean path before the syscall.
//   - Shell metacharacters in the binary name are rejected to prevent an
//     attacker-controlled $EDITOR value from injecting additional commands.
func executeEditor(editor, file string) error {
	if editor == "" {
		return fmt.Errorf("no editor specified")
	}

	// Split "editor [flags]" into tokens.  For example $EDITOR="emacs -nw"
	// becomes ["emacs", "-nw"].
	tokens := strings.Fields(editor)
	if len(tokens) == 0 {
		return fmt.Errorf("editor value is empty after splitting")
	}

	editorBin := tokens[0]
	editorArgs := tokens[1:]

	// Security: reject binary names that contain shell metacharacters to prevent
	// command injection via a malicious $EDITOR environment variable.
	for _, ch := range []string{";", "&", "|", "$", "`", "(", ")", "<", ">", "\n", "\r"} {
		if strings.Contains(editorBin, ch) {
			return fmt.Errorf("editor path contains disallowed character %q", ch)
		}
	}

	// Resolve the binary to an absolute path via PATH lookup.
	resolvedBin, err := exec.LookPath(editorBin)
	if err != nil {
		return fmt.Errorf("editor %q not found on PATH: %w", editorBin, err)
	}

	// Build argument list: pre-set flags + target file.
	var args []string
	switch {
	case strings.Contains(resolvedBin, "code"):
		// VS Code needs --wait so the CLI blocks until the tab is closed.
		args = append(args, "--wait")
	case strings.Contains(resolvedBin, "notepad++"):
		// Notepad++ flags for single-instance, no tab bar.
		args = append(args, "-multiInst", "-notabbar")
	}
	args = append(args, editorArgs...)
	args = append(args, file)

	// #nosec G204 G702
	// G204: binary is resolved via exec.LookPath (absolute path) and all shell
	// metacharacters in the editor name are rejected above, so arbitrary-binary
	// injection is not possible.
	// G702: exec.Command does NOT invoke a shell; arguments (including the file
	// path) are passed directly to the OS as a raw argv slice, so there is no
	// shell-metacharacter injection surface.  The taint warning is a false positive.
	cmd := exec.Command(resolvedBin, args...)

	// Connect to current terminal.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
