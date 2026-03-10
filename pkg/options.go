// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

// Package pkg provides the public API for Volta.
// Options are re-exported from internal/vault.
package pkg

import "github.com/gatblau/volta/internal/vault"

// Options contains vault configuration options.
// This is an alias for internal vault.Options.
type Options = vault.Options
