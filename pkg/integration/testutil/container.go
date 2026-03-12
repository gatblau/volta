// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 gatblau

package testutil

import (
	"context"
	"fmt"
	"os"

	"github.com/gatblau/volta/internal/persist"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// MinioAccessKey is the default access key for MinIO container
	MinioAccessKey = "minioadmin"
	// MinioSecretKey is the default secret key for MinIO container
	MinioSecretKey = "minioadmin"
)

// MinIOContainer holds the testcontainers MinIO instance
type MinIOContainer struct {
	Container testcontainers.Container
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
}

// StartMinIOContainer starts a MinIO testcontainer for integration testing
func StartMinIOContainer(ctx context.Context) (*MinIOContainer, error) {
	// Check if there's an existing endpoint from environment (for local testing)
	existingEndpoint := os.Getenv("S3_MINIO_ENDPOINT")
	if existingEndpoint != "" {
		return &MinIOContainer{
			Container: nil,
			Endpoint:  existingEndpoint,
			AccessKey: getEnvOrDefault("S3_MINIO_ACCESS_KEY_ID", MinioAccessKey),
			SecretKey: getEnvOrDefault("S3_MINIO_SECRET_ACCESS_KEY", MinioSecretKey),
			Bucket:    getEnvOrDefault("S3_BUCKET", "test-volta-integration"),
		}, nil
	}

	// Start a new container
	req := testcontainers.ContainerRequest{
		Image:        "minio/minio:latest",
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     MinioAccessKey,
			"MINIO_ROOT_PASSWORD": MinioSecretKey,
		},
		Cmd:        []string{"server", "/data"},
		WaitingFor: wait.ForHTTP("/minio/health/live").WithPort("9000/tcp"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start MinIO container: %w", err)
	}

	// Get the mapped port
	mappedPort, err := container.MappedPort(ctx, "9000")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("failed to get mapped port: %w", err)
	}

	endpoint := fmt.Sprintf("localhost:%s", mappedPort.Port())

	return &MinIOContainer{
		Container: container,
		Endpoint:  endpoint,
		AccessKey: MinioAccessKey,
		SecretKey: MinioSecretKey,
		Bucket:    "test-volta-integration",
	}, nil
}

// Stop stops the MinIO container
func (m *MinIOContainer) Stop(ctx context.Context) error {
	if m.Container == nil {
		return nil
	}
	return m.Container.Terminate(ctx)
}

// GetS3Config returns an S3Config configured for the MinIO container
func (m *MinIOContainer) GetS3Config(tenantID string) persist.S3Config {
	return persist.S3Config{
		Endpoint:        m.Endpoint,
		AccessKeyID:     m.AccessKey,
		SecretAccessKey: m.SecretKey,
		Bucket:          m.Bucket,
		KeyPrefix:       tenantID + "/",
		UseSSL:          false,
		Region:          "us-east-1",
	}
}

// getEnvOrDefault returns the environment variable value or a default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
