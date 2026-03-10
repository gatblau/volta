// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewLoggerWithNilConfig tests that NewLogger returns a NoOpLogger when config is nil
func TestNewLoggerWithNilConfig(t *testing.T) {
	logger, err := NewLogger(nil)
	require.NoError(t, err)
	require.NotNil(t, logger)
	_, ok := logger.(*NoOpLogger)
	assert.True(t, ok, "expected NoOpLogger for nil config")
}

// TestNewLoggerWithDisabledConfig tests that NewLogger returns a NoOpLogger when disabled
func TestNewLoggerWithDisabledConfig(t *testing.T) {
	config := &Config{
		Enabled: false,
		Type:    FileAuditType,
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	_, ok := logger.(*NoOpLogger)
	assert.True(t, ok, "expected NoOpLogger when disabled")
}

// TestNewLoggerWithNoOpType tests that NewLogger returns a NoOpLogger for NoOp type
func TestNewLoggerWithNoOpType(t *testing.T) {
	config := &Config{
		Enabled: true,
		Type:    NoOp,
	}
	logger, err := NewLogger(config)
	require.NoError(t, err)
	require.NotNil(t, logger)
	_, ok := logger.(*NoOpLogger)
	assert.True(t, ok, "expected NoOpLogger for NoOp type")
}

// TestNewLoggerWithInvalidType tests that NewLogger returns an error for unknown type
func TestNewLoggerWithInvalidType(t *testing.T) {
	config := &Config{
		Enabled: true,
		Type:    ConfigType("invalid"),
	}
	logger, err := NewLogger(config)
	assert.Error(t, err)
	assert.Nil(t, logger)
	assert.Contains(t, err.Error(), "unknown audit provider")
}

// TestFileLoggerLog tests logging events to file
func TestFileLoggerLog(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-")
	require.NoError(t, err)
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			t.Fatalf("failed to remove temp dir: %s", path)
		}
	}(tempDir)

	auditFile := filepath.Join(tempDir, "audit.log")

	logger, err := NewFileLogger(&Config{
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, logger)

	err = logger.Log("test_action", true, map[string]interface{}{
		"user": "test-user",
	})
	require.NoError(t, err)

	assert.NoError(t, logger.Close())

	fileInfo, err := os.Stat(auditFile)
	require.NoError(t, err)
	assert.Greater(t, fileInfo.Size(), int64(0), "audit log should have content")
}

// TestFileLoggerQuery tests querying events from file
func TestFileLoggerQuery(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-")
	require.NoError(t, err)
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			t.Fatalf("failed to remove temp dir: %s", path)
		}
	}(tempDir)

	auditFile := filepath.Join(tempDir, "audit.log")

	logger, err := NewFileLogger(&Config{
		TenantID: "test-tenant",
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, logger)

	for i := 0; i < 5; i++ {
		err := logger.Log("test_action", true, map[string]interface{}{
			"index": i,
		})
		require.NoError(t, err)
	}

	result, err := logger.Query(QueryOptions{
		Limit: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, result.TotalCount)
	assert.Equal(t, 5, result.Filtered)
	assert.Len(t, result.Events, 5)

	assert.NoError(t, logger.Close())
}

// TestNoOpLogger tests that NoOpLogger does nothing
func TestNoOpLogger(t *testing.T) {
	logger := NewNoOpLogger()
	require.NotNil(t, logger)

	err := logger.Log("test_action", true, nil)
	assert.NoError(t, err)

	result, err := logger.Query(QueryOptions{})
	assert.NoError(t, err)
	assert.Equal(t, 0, result.TotalCount)
	assert.Equal(t, 0, result.Filtered)
	assert.Empty(t, result.Events)

	assert.NoError(t, logger.Close())
}

// TestFileLoggerClose tests that FileLogger can be closed multiple times
func TestFileLoggerClose(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-")
	require.NoError(t, err)
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			t.Fatalf("failed to remove temp dir: %s", path)
		}
	}(tempDir)

	auditFile := filepath.Join(tempDir, "audit.log")

	logger, err := NewFileLogger(&Config{
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
	require.NoError(t, err)

	assert.NoError(t, logger.Close())
	assert.NoError(t, logger.Close())
}

// TestNewFileLoggerWithMissingPath tests that NewFileLogger returns error when file_path is missing
func TestNewFileLoggerWithMissingPath(t *testing.T) {
	_, err := NewFileLogger(&Config{
		TenantID: "test",
		Options:  map[string]interface{}{},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file_path is required")
}

// TestNewFileLoggerCreatesDirectory tests that NewFileLogger creates the directory if it doesn't exist
func TestNewFileLoggerCreatesDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-")
	require.NoError(t, err)
	defer func(path string) {
		err = os.RemoveAll(path)
		if err != nil {
			t.Fatalf("failed to remove temp dir: %s", path)
		}
	}(tempDir)

	subDir := filepath.Join(tempDir, "subdir", "logs")
	auditFile := filepath.Join(subDir, "audit.log")

	logger, err := NewFileLogger(&Config{
		TenantID: "test",
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, logger)

	fileInfo, err := os.Stat(subDir)
	require.NoError(t, err)
	assert.True(t, fileInfo.IsDir())

	assert.NoError(t, logger.Close())
}

// TestConfigTypeConstants tests that the ConfigType constants are defined correctly
func TestConfigTypeConstants(t *testing.T) {
	assert.Equal(t, ConfigType("file"), FileAuditType)
	assert.Equal(t, ConfigType("syslog"), SyslogAuditType)
	assert.Equal(t, ConfigType(""), NoOp)
}

// TestNewLoggerParseOptionsError ensures parseOptions errors bubble up
func TestNewLoggerParseOptionsError(t *testing.T) {
	config := &Config{
		Enabled: true,
		Options: map[string]interface{}{
			"file_path": []string{"not-a-string"},
		},
	}
	_, err := NewFileLogger(config)
	assert.Error(t, err)
}

// TestFileLoggerQueryWithSince exercises cache usage path
func TestFileLoggerQueryWithSince(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-cache")
	require.NoError(t, err)
	defer func(path string) {
		if err = os.RemoveAll(path); err != nil {
			t.Fatalf("failed to remove temp dir: %s", path)
		}
	}(tempDir)

	auditFile := filepath.Join(tempDir, "audit.log")

	logger, err := NewFileLogger(&Config{
		TenantID: "test",
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, logger)

	for i := 0; i < 3; i++ {
		require.NoError(t, logger.Log("cache_action", true, nil))
	}

	since := time.Now().Add(-time.Minute)
	result, err := logger.Query(QueryOptions{Since: &since, Limit: 2})
	require.NoError(t, err)
	assert.LessOrEqual(t, 2, len(result.Events))

	assert.NoError(t, logger.Close())
}

// TestFileLoggerQueryFromFile ensures file reading path is used
func TestFileLoggerQueryFromFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit-test-file")
	require.NoError(t, err)
	defer func(path string) {
		if err = os.RemoveAll(path); err != nil {
			t.Fatalf("failed to remove temp dir: %s", path)
		}
	}(tempDir)

	auditFile := filepath.Join(tempDir, "audit.log")

	logger, err := NewFileLogger(&Config{
		TenantID: "test",
		Options: map[string]interface{}{
			"file_path": auditFile,
		},
	})
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		require.NoError(t, logger.Log("file_action", i%2 == 0, map[string]interface{}{"index": i}))
	}

	twoMinutesAgo := time.Now().Add(-2 * time.Minute)
	result, err := logger.Query(QueryOptions{Since: &twoMinutesAgo, Action: "file_action", Limit: 3})
	require.NoError(t, err)
	assert.Equal(t, 5, result.Filtered)
	assert.True(t, result.TotalCount >= 5)

	assert.NoError(t, logger.Close())
}
