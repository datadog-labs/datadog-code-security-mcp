.PHONY: build test lint clean install run fmt mod help

# Version information
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Build flags
LDFLAGS = -X main.version=$(VERSION) \
          -X main.commit=$(COMMIT) \
          -X main.buildTime=$(BUILD_TIME)

# Binary name
BINARY_NAME = datadog-code-security-mcp

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "✓ Binary built: bin/$(BINARY_NAME)"

build-all: ## Build for all platforms (outputs to dist/)
	@which goreleaser > /dev/null || (echo "goreleaser not installed. Install from https://goreleaser.com/install/" && exit 1)
	goreleaser build --clean --snapshot

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.txt ./...
	@echo "✓ Tests passed"

lint: ## Run linter
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run
	@echo "✓ Linting passed"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/
	rm -rf dist/
	rm -f coverage.txt
	@echo "✓ Cleaned"

install: ## Install the binary to $GOPATH/bin
	@echo "Installing $(BINARY_NAME)..."
	go install -ldflags "$(LDFLAGS)" ./cmd/$(BINARY_NAME)
	@echo "✓ Installed to $(shell go env GOPATH)/bin/$(BINARY_NAME)"

run: ## Run the binary (for development)
	go run -ldflags "$(LDFLAGS)" ./cmd/$(BINARY_NAME)

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...
	@which goimports > /dev/null && goimports -w . || echo "Note: goimports not installed"
	@echo "✓ Code formatted"

mod: ## Tidy and verify Go modules
	@echo "Tidying modules..."
	go mod tidy
	go mod verify
	@echo "✓ Modules tidied"

.DEFAULT_GOAL := help
