// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package mem

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockDelegatesToPlatformSuccess(t *testing.T) {
	original := lockMemoryFunc
	defer func() { lockMemoryFunc = original }()

	lockMemoryFunc = func() (ProtectionLevel, error) {
		return ProtectionFull, nil
	}

	level, err := Lock()
	require.NoError(t, err)
	assert.Equal(t, ProtectionFull, level)
}

func TestLockDelegatesToPlatformError(t *testing.T) {
	original := lockMemoryFunc
	defer func() { lockMemoryFunc = original }()

	errExpected := errors.New("lock failed")
	lockMemoryFunc = func() (ProtectionLevel, error) {
		return ProtectionNone, errExpected
	}

	level, err := Lock()
	assert.Equal(t, ProtectionNone, level)
	assert.ErrorIs(t, err, errExpected)
}

func TestUnlockDelegatesToPlatform(t *testing.T) {
	original := unlockMemoryFunc
	defer func() { unlockMemoryFunc = original }()

	called := false
	unlockMemoryFunc = func() error {
		called = true
		return nil
	}

	require.NoError(t, Unlock())
	assert.True(t, called)
}

func TestUnlockReturnsError(t *testing.T) {
	original := unlockMemoryFunc
	defer func() { unlockMemoryFunc = original }()

	errExpected := errors.New("unlock failed")
	unlockMemoryFunc = func() error { return errExpected }

	err := Unlock()
	assert.ErrorIs(t, err, errExpected)
}
