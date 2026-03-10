// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package mem

// ProtectionLevel indicates how well the vault can protect memory
type ProtectionLevel int

const (
	ProtectionNone    ProtectionLevel = iota // No memory protection available
	ProtectionPartial                        // Some protection measures applied
	ProtectionFull                           // Full memory protection (locked memory)
)

// Lock attempts to prevent sensitive data from being swapped to disk
// Returns the protection level achieved and any error encountered
var (
	lockMemoryFunc   = lockMemoryPlatform
	unlockMemoryFunc = unlockMemoryPlatform
)

func Lock() (ProtectionLevel, error) {
	return lockMemoryFunc()
}

// Unlock releases memory locks if they were applied
func Unlock() error {
	return unlockMemoryFunc()
}
