// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package misc

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsNotFoundError tests the IsNotFoundError function
func TestIsNotFoundError(t *testing.T) {
	// Test with nil error
	result := IsNotFoundError(nil)
	assert.False(t, result, "nil error should return false")

	// Test with "not found" in message
	err := errors.New("file not found")
	result = IsNotFoundError(err)
	assert.True(t, result, "error containing 'not found' should return true")

	// Test with "does not exist" in message
	err = errors.New("resource does not exist")
	result = IsNotFoundError(err)
	assert.True(t, result, "error containing 'does not exist' should return true")

	// Test with "no such file" in message
	err = errors.New("no such file or directory")
	result = IsNotFoundError(err)
	assert.True(t, result, "error containing 'no such file' should return true")

	// Test with unrelated error
	err = errors.New("permission denied")
	result = IsNotFoundError(err)
	assert.False(t, result, "unrelated error should return false")

	// Test with empty error message
	err = errors.New("")
	result = IsNotFoundError(err)
	assert.False(t, result, "empty error message should return false")
}
