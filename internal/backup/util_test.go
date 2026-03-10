// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package backup

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGenerateBackupID tests that GenerateBackupID produces valid IDs
func TestGenerateBackupID(t *testing.T) {
	// Generate IDs and verify format
	for i := 0; i < 10; i++ {
		id := GenerateBackupID()

		// Check format: backup_<timestamp>_<hex>
		pattern := regexp.MustCompile(`^backup_\d+_[a-f0-9]{16}$`)
		assert.True(t, pattern.MatchString(id), "ID %s does not match expected format", id)
	}
}

// TestGenerateBackupIDFormat tests the specific format of the backup ID
func TestGenerateBackupIDFormat(t *testing.T) {
	id := GenerateBackupID()

	// Should start with "backup_"
	assert.True(t, len(id) > 8, "ID should be longer than 8 characters")
	assert.Contains(t, id, "backup_")

	// Should have a timestamp part
	pattern := regexp.MustCompile(`backup_\d+_`)
	assert.True(t, pattern.MatchString(id), "ID should have timestamp in format backup_<number>_")

	// Should have a hex part at the end
	hexPattern := regexp.MustCompile(`[a-f0-9]{16}$`)
	assert.True(t, hexPattern.MatchString(id), "ID should end with 16 hex characters")
}
