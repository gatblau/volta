// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package misc

import "strings"

func IsNotFoundError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "does not exist") ||
		strings.Contains(errStr, "no such file")
}
