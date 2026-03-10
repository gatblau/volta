package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gatblau/volta/pkg"
)

const (
	// IMPORTANT: ensure the passphrase remains the same for the creation and restoration of the backup and the creation of a vault that will
	// be backed up and restored
	passphrase = "Z5vmvP3^6UE*YwvjPZ5qZRJ7FoArSN57MRCQ@9fV2V7y&X3efYXht*LV#vX8"
)

func main() {
	fmt.Println("### Example: Vault Backup and Restore Operations with Data Integrity Verification ###")
	fmt.Printf("🎯 Goal: Demonstrate complete backup/restore cycle with encrypted PII and secrets\n\n")

	// 1. Configure VaultManager Options.
	options := pkg.Options{
		DerivationPassphrase: passphrase,
		EnableMemoryLock:     true,
	}
	fmt.Println("✅ VaultManager options configured")

	// 2. Initialise the audit logger.
	auditFilePath, _ := os.MkdirTemp("", "audit-log-")
	auditFile := filepath.Join(auditFilePath, "pkg.log")
	auditLogger, err := createAuditLogger(auditFile)
	if err != nil {
		log.Fatalf("❌ Failed to create audit logger: %v", err)
	}
	fmt.Println("✅ Audit logger initialized")

	defer func(path string) {
		fmt.Printf("✅ Audit logger removed: %s\n", path)
		if err = os.RemoveAll(path); err != nil {
			fmt.Printf("Failed to remove %q: %v\n", path, err)
		}
	}(auditFilePath)

	// 3. Create directories for backup/restore
	basePath, _ := os.MkdirTemp("", "backup-test-vault-")
	backupFileName := "vault_backup.vault"
	backupDestination, _ := os.MkdirTemp("", "backup-temp-test-")

	// Clean the directory if it already exists
	if _, err = os.Stat(basePath); err == nil {
		_ = os.RemoveAll(basePath)
	}

	defer func() {
		cleanupPaths := []string{basePath, backupDestination}
		for _, path := range cleanupPaths {
			if err = os.RemoveAll(path); err != nil {
				fmt.Printf("⚠️ Failed to remove directory %s: %v\n", path, err)
			} else {
				fmt.Printf("✅ Cleaned up directory: %s\n", path)
			}
		}
	}()

	fmt.Printf("✅ Using temporary vault storage at: %s\n", basePath)

	// 4. Create the VaultManager instance.
	vaultManager := pkg.NewVaultManagerFileStore(options, basePath, auditLogger)
	fmt.Println("✅ VaultManager initialized successfully")

	// --- Initial Data Setup and Population ---
	fmt.Println("\n--- 🔐 Initial Data Setup and Population ---")
	tenantID := "backup-restore-service"

	vault, err := vaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("❌ Failed to get vault for tenant %s", tenantID)
	}

	// Populate vault with test secrets
	fmt.Println("\n✅ Populating Vault with Test Data...")
	secrets := map[string][]byte{
		"secret_1": []byte("4eC39HqLyjWDarjtT1zdp7dc"),
		"secret_2": []byte("SuperSecureDBP@ssw0rd123!"),
		"secret_3": []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"),
		"secret_4": []byte("abc123def456ghi789jkl012mno345pqr678"),
	}

	for id, data := range secrets {
		_, err = vault.StoreSecret(id, data, nil, pkg.ContentTypeText)
		if err != nil {
			log.Fatalf("❌ Failed to store secret %s: %v", id, err)
		}
		fmt.Printf("✅ Secret %s stored\n", id)
	}

	// Perform backup operation
	fmt.Println("\n--- 💾 Vault Backup Operation ---")
	err = vault.Backup(backupFileName, passphrase)
	if err != nil {
		log.Fatalf("❌ Failed to backup vault: %v", err)
	}
	fmt.Printf("✅ Backup completed successfully: %s\n", backupFileName)

	// 5. Copy the backup to a safe location
	err = copyBackupFile(filepath.Join(basePath, tenantID, "backups", backupFileName), backupDestination)
	if err != nil {
		log.Fatalf("❌ Failed to copy backup file to destination: %v", err)
	}
	fmt.Printf("✅ Backup file copied to safe location: %s\n", backupDestination)

	// Clean the original Vault data
	if err = vault.Close(); err != nil {
		log.Fatalf("❌ Failed to close original vault: %v", err)
	}

	if err = os.RemoveAll(basePath); err != nil {
		log.Fatalf("❌ Failed to simulate loss of vault data: %v", err)
	}
	fmt.Println("✅ Original vault data removed (simulated loss)")

	// Restore from backup
	fmt.Println("\n--- 📥 Vault Restore Operation ---")
	newVaultManager := pkg.NewVaultManagerFileStore(options, basePath, auditLogger)
	restoreVault, err := newVaultManager.GetVault(tenantID)
	if err != nil {
		log.Fatalf("❌ Failed to get vault for restoration")
	}

	backupLocation, err := filepath.Abs(filepath.Join(backupDestination, backupFileName))
	if err != nil {
		log.Fatalf("❌ Failed to get backup location: %v", err)
	}

	err = restoreVault.Restore(backupLocation, passphrase)
	if err != nil {
		log.Fatalf("❌ Failed to restore vault: %v", err)
	}
	fmt.Println("✅ Restore completed successfully")

	// Verify restored secrets
	fmt.Println("\n--- 🔍 Verifying Restored Data Integrity ---")
	for id, originalData := range secrets {
		result, err := restoreVault.GetSecret(id)
		if err != nil {
			log.Fatalf("❌ Failed to retrieve restored secret %s: %v", id, err)
		}
		if !bytes.Equal(result.Data, originalData) {
			log.Fatalf("❌ Data integrity check failed for %s", id)
		}
		fmt.Printf("✅ Restored secret %s verified\n", id)
	}

	fmt.Println("\n### 🎉 Backup and Restore Example Completed Successfully ###")
}

// safeFileNameRe matches only alphanumeric characters, hyphens, underscores, and dots,
// with no path separators or traversal sequences, to produce a taint-free filename.
var safeFileNameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-][a-zA-Z0-9_\-.]*$`)

// copyBackupFile copies the backup file to the specified destination.
// Security (G301/G306): backup directories and files contain sensitive encrypted
// vault data and must not be world-readable.
// Security (G703/G304): Use os.Root (Go ≥1.24) to scope all I/O to their
// respective directories, enforcing path containment at the OS level.
func copyBackupFile(src, dstDir string) error {
	// Validate and sanitise the destination directory.
	cleanDstDir := filepath.Clean(dstDir)
	if strings.Contains(cleanDstDir, "..") {
		return fmt.Errorf("invalid destination directory: potential path traversal detected")
	}

	// Validate the filename from src against a strict allowlist regex before
	// any I/O. The regex-match result is used (not the raw input) to avoid
	// carrying a tainted value through to file operations.
	rawName := filepath.Base(src)
	if !safeFileNameRe.MatchString(rawName) {
		return fmt.Errorf("invalid filename %q: must contain only alphanumeric characters, hyphens, underscores, or dots", rawName)
	}
	safeFileName := safeFileNameRe.FindString(rawName)

	// G304: Open an os.Root anchored to the source's parent directory (Go ≥1.24).
	// All reads are scoped to that directory; traversal above it is impossible.
	srcRoot, err := os.OpenRoot(filepath.Dir(src))
	if err != nil {
		return fmt.Errorf("cannot open source directory: %w", err)
	}
	defer func(srcRoot *os.Root) {
		err = srcRoot.Close()
		if err != nil {
			fmt.Print(err)
		}
	}(srcRoot)

	srcFile, err := srcRoot.Open(safeFileName)
	if err != nil {
		return fmt.Errorf("cannot open source file: %w", err)
	}
	input, readErr := io.ReadAll(srcFile)
	closeErr := srcFile.Close()
	if readErr != nil {
		return fmt.Errorf("cannot read source file: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("cannot close source file: %w", closeErr)
	}

	// Create destination directory with secure permissions.
	// 0750 — owner read/write/execute, group read/execute, no world access.
	if err = os.MkdirAll(cleanDstDir, 0750); err != nil {
		return err
	}

	// G703: Open an os.Root anchored to the destination directory (Go ≥1.24).
	// All writes are contained within cleanDstDir at the OS level; any attempt
	// to escape via traversal sequences is rejected by the kernel.
	dstRoot, err := os.OpenRoot(cleanDstDir)
	if err != nil {
		return fmt.Errorf("cannot open destination directory: %w", err)
	}
	defer func(dstRoot *os.Root) {
		if err = dstRoot.Close(); err != nil {
			fmt.Print(err)
		}
	}(dstRoot)

	// 0600 — owner read/write only; backup contains encrypted secrets.
	dstFile, err := dstRoot.OpenFile(safeFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot create destination file: %w", err)
	}
	if err = dstRoot.Close(); err != nil {
		fmt.Print(err)
	}

	_, err = dstFile.Write(input)
	return err
}

// createAuditLogger initializes a logger for recording audit events.
func createAuditLogger(auditFile string) (pkg.Logger, error) {
	fmt.Printf("✅ Initializing file-based audit logger to: %s\n", auditFile)
	return pkg.NewLogger(&pkg.Config{
		Enabled: true,
		Type:    pkg.FileAuditType,
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
}
