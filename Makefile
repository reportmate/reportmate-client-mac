# ReportMate macOS Client Makefile
# Provides convenient build targets

.PHONY: build clean test install release help

# Configuration
PROJECT_NAME = ReportMate
BINARY_NAME = managedreportsrunner
VERSION ?= $(shell date +%Y.%m.%d.%H%M)

# Default target
help:
	@echo "ReportMate macOS Client Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build     - Build the project in debug mode"
	@echo "  release   - Build the project in release mode" 
	@echo "  test      - Run tests"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install locally for testing"
	@echo "  package   - Create distribution packages"
	@echo "  sign      - Build and code sign"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION   - Set build version (default: $(VERSION))"

# Build targets
build:
	@echo "Building $(PROJECT_NAME) in debug mode..."
	@./build.sh --debug --skip-pkg --skip-zip --skip-dmg

release:
	@echo "Building $(PROJECT_NAME) in release mode..."
	@./build.sh --skip-pkg --skip-zip --skip-dmg

# Test targets
test:
	@echo "Running tests..."
	swift test

# Packaging targets
package:
	@echo "Creating distribution packages..."
	./build.sh --version $(VERSION)

sign:
	@echo "Building and signing..."
	./build.sh --version $(VERSION) --sign

# Development targets
clean:
	@echo "Cleaning build artifacts..."
	swift package clean
	rm -rf build/
	rm -rf .build/

install: release
	@echo "Installing $(BINARY_NAME) for local testing..."
	sudo mkdir -p /usr/local/reportmate
	sudo cp .build/release/$(BINARY_NAME) /usr/local/reportmate/
	sudo chmod +x /usr/local/reportmate/$(BINARY_NAME)
	@echo "Installed to /usr/local/reportmate/$(BINARY_NAME)"
	@echo "Test with: /usr/local/reportmate/$(BINARY_NAME) --help"

# Development convenience targets
dev-setup:
	@echo "Setting up development environment..."
	@if ! command -v osqueryi >/dev/null 2>&1; then \
		echo "Installing osquery via Homebrew..."; \
		brew install osquery; \
	else \
		echo "osquery already installed"; \
	fi

format:
	@echo "Formatting Swift code..."
	@if command -v swift-format >/dev/null 2>&1; then \
		swift-format --in-place --recursive Sources/ Tests/; \
	else \
		echo "swift-format not installed. Install with: brew install swift-format"; \
	fi

lint:
	@echo "Linting Swift code..."
	@if command -v swiftlint >/dev/null 2>&1; then \
		swiftlint; \
	else \
		echo "SwiftLint not installed. Install with: brew install swiftlint"; \
	fi