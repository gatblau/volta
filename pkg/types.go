// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

// Package pkg provides the public API surface for the Volta vault service.
// This package contains the public types and interfaces that external consumers
// can import and use.
//
// NOTE: This package re-exports types from internal/vault to provide a stable
// public API. The internal implementation types are aliased here to ensure
// type compatibility across the public interface.
package pkg

import (
	"github.com/gatblau/volta/internal/vault"
)

// Re-export types from internal/vault for public API stability
// These type aliases ensure that pkg.VaultService and internal types are compatible

// KeyStatus is an alias for vault.KeyStatus
type KeyStatus = vault.KeyStatus

// CryptoAlgorithm is an alias for vault.CryptoAlgorithm
type CryptoAlgorithm = vault.CryptoAlgorithm

// ContentType is an alias for vault.ContentType
type ContentType = vault.ContentType

// Re-export ContentType constants for convenience
var (
	ContentTypeText   = vault.ContentTypeText
	ContentTypeJSON   = vault.ContentTypeJSON
	ContentTypeTOML   = vault.ContentTypeTOML
	ContentTypeXML    = vault.ContentTypeXML
	ContentTypeYAML   = vault.ContentTypeYAML
	ContentTypePEM    = vault.ContentTypePEM
	ContentTypeBinary = vault.ContentTypeBinary
)

// KeyStatus constants
var (
	KeyStatusActive   = vault.KeyStatusActive
	KeyStatusInactive = vault.KeyStatusInactive
)

// CryptoAlgorithm constants
var (
	ChaCha20Poly1305 = vault.ChaCha20Poly1305
)

// SecretResult is an alias for vault.SecretResult
type SecretResult = vault.SecretResult

// SecretsContainer is an alias for vault.SecretsContainer
type SecretsContainer = vault.SecretsContainer

// SecretEntry is an alias for vault.SecretEntry
type SecretEntry = vault.SecretEntry

// SecretMetadata is an alias for vault.SecretMetadata
type SecretMetadata = vault.SecretMetadata

// SecretListEntry is an alias for vault.SecretListEntry
type SecretListEntry = vault.SecretListEntry

// SecretListOptions is an alias for vault.SecretListOptions
type SecretListOptions = vault.SecretListOptions

// KeyMetadata is an alias for vault.KeyMetadata
type KeyMetadata = vault.KeyMetadata

// SecretWithContext is an alias for vault.SecretWithContext
type SecretWithContext = vault.SecretWithContext
