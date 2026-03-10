// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

// Package pkg provides the public API for Volta.
// Types and interfaces for storage backends are re-exported from internal/persist.
package pkg

import (
	"github.com/gatblau/volta/internal/persist"
)

// Store is the interface for persisting vault data.
type Store = persist.Store

// VersionedData represents data with its version information.
type VersionedData = persist.VersionedData

// BackupContainer represents the outer backup format with metadata.
type BackupContainer = persist.BackupContainer

// BackupData represents the actual vault data to be backed up.
type BackupData = persist.BackupData

// BackupInfo holds essential metadata about a backup.
type BackupInfo = persist.BackupInfo

// DetailedBackupInfo provides detailed information regarding a backup.
type DetailedBackupInfo = persist.DetailedBackupInfo

// StoreConfig provides configuration for different storage backends.
type StoreConfig = persist.StoreConfig

// StoreType represents the different types of storage backends.
type StoreType = persist.StoreType

// ConcurrencyError represents version conflict errors.
type ConcurrencyError = persist.ConcurrencyError

// Supported storage types.
const (
	StoreTypeFileSystem = persist.StoreTypeFileSystem
	StoreTypeS3         = persist.StoreTypeS3
)

// NewStore factory function to create storage backends.
var NewStore = persist.NewStore

// NewFileSystemStore creates a new FileSystemStore.
var NewFileSystemStore = persist.NewFileSystemStore

// NewFileSystemStoreFromConfig creates a FileSystemStore from StoreConfig.
var NewFileSystemStoreFromConfig = persist.NewFileSystemStoreFromConfig

// NewS3Store creates a new S3Store.
var NewS3Store = persist.NewS3Store

// NewS3StoreFromConfig creates a new S3Store from StoreConfig.
var NewS3StoreFromConfig = persist.NewS3StoreFromConfig
