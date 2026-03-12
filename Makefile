# Makefile for release-engine

.PHONY: lint test test-smoke test-integration security

# Check if golangci-lint is installed, if not install it
lint-check:
	@echo "Checking if golangci-lint is installed..."
	@which golangci-lint || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)

# Run golangci-lint
lint: lint-check
	@echo "Running linter..."
	@golangci-lint run ./...

# Run tests with coverage (excluding smoke tests and examples - they have no production code to cover)
test:
	@echo "Running tests with coverage..."
	@COVERPKG=$$(go list ./pkg/... ./internal/... | tr '\n' ',' | sed 's/,$$//'); \
	go test -tags=integration -v -timeout 30m -coverpkg=$$COVERPKG -coverprofile=coverage.out $$(go list ./pkg/... ./internal/...)
	@go tool cover -func=coverage.out

# Run smoke tests (containers verification - no production code to cover)
test-smoke:
	@echo "Running smoke tests (container verification)..."
	@go test -tags=integration -v ./internal/smoke/...

# Run integration tests (requires Docker for testcontainers)
test-integration:
	@echo "Running integration tests..."
	@go test -v -timeout 30m ./pkg/integration/...

test-race:
	@echo "Running tests with race detection..."
	@go test -race -count=1 ./...

# Run security checks (go install github.com/securego/gosec/v2/cmd/gosec@latest)
security:
	@echo "Running security checks..."
	@go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude=G101 -quiet ./...