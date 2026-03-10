// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

// Package pkg provides the public API for Volta.
// Audit logging types are re-exported from internal/audit.
package pkg

import (
	"github.com/gatblau/volta/internal/audit"
)

// Config defines audit logging configuration
type Config = audit.Config

// ConfigType is the type of audit configuration
type ConfigType = audit.ConfigType

// Logger interface for pluggable audit implementations
type Logger = audit.Logger

// Event represents an audit log event
type Event = audit.Event

// QueryOptions for filtering audit logs
type QueryOptions = audit.QueryOptions

// QueryResult contains the results of an audit query
type QueryResult = audit.QueryResult

// NewLogger creates an appropriate logger based on configuration
var NewLogger = audit.NewLogger

// FileOptions for file-based audit logging
type FileOptions = audit.FileOptions

// NewFileLogger creates a new file-based audit logger
var NewFileLogger = audit.NewFileLogger

// SyslogOptions for syslog-based audit logging
type SyslogOptions = audit.SyslogOptions

// NewSyslogLogger creates a new syslog audit logger with options
var NewSyslogLogger = audit.NewSyslogLogger

// NewNoOpLogger creates a new no-op logger
var NewNoOpLogger = audit.NewNoOpLogger

// NoOpLogger is a no-op implementation for when auditing is disabled
type NoOpLogger = audit.NoOpLogger

// Audit types
const (
	FileAuditType   = audit.FileAuditType
	SyslogAuditType = audit.SyslogAuditType
	NoOp            = audit.NoOp
)
