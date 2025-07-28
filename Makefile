# Zippys - Zip Slip Security Tool Makefile
# Author: copyleftdev
# Version: 1.0.0

# Variables
BINARY_NAME=zippys
BINARY_UNIX=$(BINARY_NAME)_unix
BINARY_WINDOWS=$(BINARY_NAME).exe
BINARY_DARWIN=$(BINARY_NAME)_darwin
VERSION=1.0.0
BUILD_TIME=$(shell date +%Y-%m-%d_%H:%M:%S)
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
BLUE=\033[0;34m
NC=\033[0m # No Color

.PHONY: all build clean test coverage deps fmt vet lint install uninstall run-tests run-fuzz help

# Default target
all: clean deps fmt vet test build

# Build the binary
build:
	@echo "$(BLUE)🔨 Building $(BINARY_NAME)...$(NC)"
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v

# Build for multiple platforms
build-all: build-linux build-windows build-darwin
	@echo "$(GREEN)✅ All platform builds completed!$(NC)"

build-linux:
	@echo "$(BLUE)🐧 Building for Linux...$(NC)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_UNIX) -v

build-windows:
	@echo "$(BLUE)🪟 Building for Windows...$(NC)"
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_WINDOWS) -v

build-darwin:
	@echo "$(BLUE)🍎 Building for macOS...$(NC)"
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_DARWIN) -v

# Clean build artifacts
clean:
	@echo "$(YELLOW)🧹 Cleaning build artifacts...$(NC)"
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)
	rm -f $(BINARY_WINDOWS)
	rm -f $(BINARY_DARWIN)
	rm -rf dist/
	rm -f coverage.out
	rm -f coverage.html

# Install dependencies
deps:
	@echo "$(BLUE)📦 Installing dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
fmt:
	@echo "$(BLUE)✨ Formatting code...$(NC)"
	$(GOFMT) ./...

# Vet code
vet:
	@echo "$(BLUE)🔍 Vetting code...$(NC)"
	$(GOVET) ./...

# Run tests
test:
	@echo "$(BLUE)🧪 Running tests...$(NC)"
	$(GOTEST) -v ./...

# Run tests with coverage
coverage:
	@echo "$(BLUE)📊 Running tests with coverage...$(NC)"
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✅ Coverage report generated: coverage.html$(NC)"

# Run fuzz tests
fuzz:
	@echo "$(BLUE)🎯 Running fuzz tests...$(NC)"
	$(GOTEST) -fuzz=FuzzPathVulnerabilityDetection -fuzztime=30s
	$(GOTEST) -fuzz=FuzzGenerateAndScanZip -fuzztime=30s
	$(GOTEST) -fuzz=FuzzAdversarialInputs -fuzztime=30s

# Run comprehensive tests (unit + integration + fuzz)
test-all: test coverage fuzz
	@echo "$(GREEN)✅ All tests completed!$(NC)"

# Run the built tool's internal tests
run-tests: build
	@echo "$(BLUE)🔬 Running tool's internal test suite...$(NC)"
	./$(BINARY_NAME) test

# Run test data validation
test-data: build
	@echo "$(BLUE)📋 Running test data validation...$(NC)"
	./run_testdata.sh

# Install the binary to system PATH
install: build
	@echo "$(BLUE)📥 Installing $(BINARY_NAME) to /usr/local/bin...$(NC)"
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "$(GREEN)✅ $(BINARY_NAME) installed successfully!$(NC)"

# Uninstall the binary from system PATH
uninstall:
	@echo "$(YELLOW)🗑️ Uninstalling $(BINARY_NAME)...$(NC)"
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)✅ $(BINARY_NAME) uninstalled successfully!$(NC)"

# Create distribution package
dist: clean build-all
	@echo "$(BLUE)📦 Creating distribution package...$(NC)"
	mkdir -p dist
	cp $(BINARY_UNIX) dist/$(BINARY_NAME)-$(VERSION)-linux-amd64
	cp $(BINARY_WINDOWS) dist/$(BINARY_NAME)-$(VERSION)-windows-amd64.exe
	cp $(BINARY_DARWIN) dist/$(BINARY_NAME)-$(VERSION)-darwin-amd64
	cp README.md dist/
	cp -r media dist/
	# Copy testdata if it exists (optional for distribution)
	@if [ -d "testdata" ]; then cp -r testdata dist/; else echo "$(YELLOW)⚠️  testdata directory not found, skipping...$(NC)"; fi
	cd dist && tar -czf $(BINARY_NAME)-$(VERSION).tar.gz --exclude='*.tar.gz' * && cd ..
	@echo "$(GREEN)✅ Distribution package created: dist/$(BINARY_NAME)-$(VERSION).tar.gz$(NC)"

# Development workflow
dev: clean deps fmt vet test build
	@echo "$(GREEN)🚀 Development build completed!$(NC)"

# Quick build for development
quick:
	@echo "$(BLUE)⚡ Quick build...$(NC)"
	$(GOBUILD) -o $(BINARY_NAME) -v

# Run security scan
security:
	@echo "$(BLUE)🔒 Running security scan...$(NC)"
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "$(YELLOW)⚠️ gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest$(NC)"; \
	fi

# Run linter
lint:
	@echo "$(BLUE)🔍 Running linter...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)⚠️ golangci-lint not installed. Install from: https://golangci-lint.run/usage/install/$(NC)"; \
	fi

# Generate documentation
docs:
	@echo "$(BLUE)📚 Generating documentation...$(NC)"
	@if command -v godoc >/dev/null 2>&1; then \
		echo "$(GREEN)✅ Documentation server: http://localhost:6060/pkg/$(shell go list -m)/$(NC)"; \
		godoc -http=:6060; \
	else \
		echo "$(YELLOW)⚠️ godoc not installed. Install with: go install golang.org/x/tools/cmd/godoc@latest$(NC)"; \
	fi

# Benchmark tests
bench:
	@echo "$(BLUE)⏱️ Running benchmarks...$(NC)"
	$(GOTEST) -bench=. -benchmem ./...

# Profile the application
profile: build
	@echo "$(BLUE)📊 Running CPU profiling...$(NC)"
	./$(BINARY_NAME) test -cpuprofile=cpu.prof
	@if command -v go-torch >/dev/null 2>&1; then \
		go-torch cpu.prof; \
		echo "$(GREEN)✅ Flame graph generated: torch.svg$(NC)"; \
	fi

# Check for updates
update:
	@echo "$(BLUE)🔄 Checking for dependency updates...$(NC)"
	$(GOGET) -u ./...
	$(GOMOD) tidy

# Show project status
status:
	@echo "$(BLUE)📊 Project Status$(NC)"
	@echo "=================="
	@echo "Binary: $(BINARY_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo ""
	@echo "$(BLUE)📁 Project Structure:$(NC)"
	@find . -name "*.go" | wc -l | xargs echo "Go files:"
	@find testdata -name "*.zip" 2>/dev/null | wc -l | xargs echo "Test ZIP files:"
	@find media -name "*.txt" -o -name "*.png" 2>/dev/null | wc -l | xargs echo "Media assets:"

# Demo the tool
demo: build
	@echo "$(BLUE)🎬 Running Zippys demo...$(NC)"
	@echo "$(YELLOW)1. Running internal tests...$(NC)"
	./$(BINARY_NAME) test
	@echo ""
	@echo "$(YELLOW)2. Scanning test data...$(NC)"
	./$(BINARY_NAME) scan testdata/vulnerable/*.zip
	@echo ""
	@echo "$(GREEN)✅ Demo completed!$(NC)"

# Help target
help:
	@echo "$(BLUE)Zippys - Zip Slip Security Tool Makefile$(NC)"
	@echo "=========================================="
	@echo ""
	@echo "$(YELLOW)Build Commands:$(NC)"
	@echo "  build         Build the binary for current platform"
	@echo "  build-all     Build for all platforms (Linux, Windows, macOS)"
	@echo "  build-linux   Build for Linux"
	@echo "  build-windows Build for Windows"
	@echo "  build-darwin  Build for macOS"
	@echo "  quick         Quick development build"
	@echo ""
	@echo "$(YELLOW)Development Commands:$(NC)"
	@echo "  dev           Full development workflow (clean, deps, fmt, vet, test, build)"
	@echo "  deps          Install/update dependencies"
	@echo "  fmt           Format code"
	@echo "  vet           Vet code for issues"
	@echo "  lint          Run linter (requires golangci-lint)"
	@echo "  security      Run security scan (requires gosec)"
	@echo ""
	@echo "$(YELLOW)Testing Commands:$(NC)"
	@echo "  test          Run unit tests"
	@echo "  test-all      Run all tests (unit, coverage, fuzz)"
	@echo "  coverage      Run tests with coverage report"
	@echo "  fuzz          Run fuzz tests"
	@echo "  run-tests     Run tool's internal test suite"
	@echo "  test-data     Run test data validation"
	@echo "  bench         Run benchmark tests"
	@echo ""
	@echo "$(YELLOW)Distribution Commands:$(NC)"
	@echo "  dist          Create distribution package"
	@echo "  install       Install binary to system PATH"
	@echo "  uninstall     Remove binary from system PATH"
	@echo ""
	@echo "$(YELLOW)Utility Commands:$(NC)"
	@echo "  clean         Clean build artifacts"
	@echo "  docs          Generate and serve documentation"
	@echo "  profile       Run CPU profiling"
	@echo "  update        Update dependencies"
	@echo "  status        Show project status"
	@echo "  demo          Run tool demonstration"
	@echo "  help          Show this help message"
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make dev      # Full development build"
	@echo "  make test-all # Run comprehensive tests"
	@echo "  make dist     # Create release package"
	@echo "  make demo     # See the tool in action"
