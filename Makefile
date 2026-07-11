# TraceSleuth - unified build pipeline
# React frontend -> embedded Go binary

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
BINARY_NAME  := tracesleuth
VERSION_FILE := VERSION
VERSION      := $(shell tr -d '\r\n' < $(VERSION_FILE) 2>/dev/null)
BUILD_DIR    := build
CMD_DIR      := cmd/sdwan-triage
DIST_DIR     := $(CMD_DIR)/dist
FRONTEND_DIR := web/frontend
GEOIP_DIR    := data
GEOIP_DB     := $(GEOIP_DIR)/GeoLite2-City.mmdb
GO           := go
NPM          := npm
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE         := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS      := -s -w \
                 -X main.version=$(VERSION) \
                 -X main.buildCommit=$(COMMIT) \
                 -X main.buildDate=$(DATE)
GOFLAGS      := -ldflags '$(LDFLAGS)'

ifeq ($(strip $(VERSION)),)
$(error VERSION file is missing or empty)
endif

.PHONY: all build build-frontend copy-dist copy-geoip build-backend build-all \
        build-linux build-darwin build-windows release github-release \
        clean clean-all test test-coverage test-race \
        lint fmt fmt-check vet run run-web help \
        setup-geoip check-geoip frontend-dev install check-version

# -----------------------------------------------------------------------------
# Default
# -----------------------------------------------------------------------------
all: build

check-version:
	@bash scripts/check-version-contract.sh

# -----------------------------------------------------------------------------
# Frontend
# -----------------------------------------------------------------------------
build-frontend:
	@echo "Building TraceSleuth React frontend..."
	cd $(FRONTEND_DIR) && $(NPM) ci && $(NPM) run build
	@echo "Frontend built: $(FRONTEND_DIR)/dist"

copy-dist: build-frontend
	@echo "Copying frontend distribution into the Go embed directory..."
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)
	cp -R $(FRONTEND_DIR)/dist/. $(DIST_DIR)/
	@echo "Frontend staged: $(DIST_DIR)"

# -----------------------------------------------------------------------------
# Optional GeoIP embedding
# -----------------------------------------------------------------------------
copy-geoip:
	@if [ -f "$(GEOIP_DB)" ]; then \
		echo "Embedding GeoIP database..."; \
		mkdir -p $(CMD_DIR)/data; \
		cp $(GEOIP_DB) $(CMD_DIR)/data/GeoLite2-City.mmdb; \
		echo "GeoIP database staged for embed"; \
	else \
		echo "GeoIP database not found at $(GEOIP_DB); the binary will use the inherited disk fallback where applicable"; \
		mkdir -p $(CMD_DIR)/data; \
		touch $(CMD_DIR)/data/.gitkeep; \
	fi

# -----------------------------------------------------------------------------
# Backend and unified build
# -----------------------------------------------------------------------------
build-backend: check-version copy-geoip
	@echo "Building $(BINARY_NAME) v$(VERSION) ($(COMMIT))..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

build: copy-dist build-backend
	@echo ""
	@echo "=================================================="
	@echo "  $(BINARY_NAME) v$(VERSION) ready"
	@echo "  Binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "  Commit: $(COMMIT)"
	@echo "  Date:   $(DATE)"
	@echo "=================================================="

# -----------------------------------------------------------------------------
# Cross-compilation
# -----------------------------------------------------------------------------
build-linux: copy-dist check-version
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)

build-darwin: copy-dist check-version
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	@if command -v codesign >/dev/null 2>&1; then \
		codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64; \
		codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64; \
	else \
		echo "codesign unavailable; macOS binaries remain unsigned"; \
	fi

build-windows: copy-dist check-version
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)

build-all: build-linux build-darwin build-windows

# -----------------------------------------------------------------------------
# Release artifacts
# -----------------------------------------------------------------------------
release: clean copy-dist check-version
	@echo "Building TraceSleuth release v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)

	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./$(CMD_DIR)
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-amd64

	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./$(CMD_DIR)
	@if command -v codesign >/dev/null 2>&1; then codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64; fi
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-amd64

	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./$(CMD_DIR)
	@if command -v codesign >/dev/null 2>&1; then codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64; fi
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-darwin-arm64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-arm64

	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./$(CMD_DIR)
	zip -j $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-windows-amd64.zip $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe

	@echo "Generating SHA-256 checksums..."
	cd $(BUILD_DIR) && shasum -a 256 *.tar.gz *.zip > checksums-v$(VERSION).txt
	@ls -lh $(BUILD_DIR)/*.tar.gz $(BUILD_DIR)/*.zip $(BUILD_DIR)/checksums-*.txt

github-release: release
	@command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) is required" >&2; exit 1; }
	@gh auth status >/dev/null 2>&1 || { echo "GitHub CLI is not authenticated" >&2; exit 1; }
	gh release create v$(VERSION) \
		$(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-linux-amd64.tar.gz \
		$(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-darwin-amd64.tar.gz \
		$(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-darwin-arm64.tar.gz \
		$(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-windows-amd64.zip \
		$(BUILD_DIR)/checksums-v$(VERSION).txt \
		--title "TraceSleuth v$(VERSION)" \
		--notes-file RELEASE_NOTES.md \
		--draft
	@echo "Draft release created: https://github.com/DanielDietz-de/TraceSleuth/releases"

install: copy-dist check-version
	$(GO) install $(GOFLAGS) ./$(CMD_DIR)

# -----------------------------------------------------------------------------
# Tests and code quality
# -----------------------------------------------------------------------------
test:
	$(GO) test ./... -v -count=1 -timeout 120s

test-coverage:
	$(GO) test ./... -coverprofile=coverage.out -timeout 120s
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-race:
	$(GO) test ./... -race -count=1 -timeout 240s

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$(gofmt -l $$(find . -type f -name '*.go' -not -path './web/releases/*' -not -path './releases/*'))"; \
	if [ -n "$$unformatted" ]; then printf 'Unformatted Go files:\n%s\n' "$$unformatted" >&2; exit 1; fi

vet:
	$(GO) vet ./...

lint: fmt-check vet
	@echo "Code quality checks passed"

# -----------------------------------------------------------------------------
# GeoIP database
# -----------------------------------------------------------------------------
setup-geoip:
	@mkdir -p $(GEOIP_DIR)
	@chmod +x scripts/download_geoip.sh
	@scripts/download_geoip.sh $(GEOIP_DIR)

check-geoip:
	@if [ -f "$(GEOIP_DB)" ]; then \
		echo "GeoIP database found: $(GEOIP_DB)"; \
		ls -lh $(GEOIP_DB); \
	else \
		echo "GeoIP database not found. Run: make setup-geoip"; \
	fi

# -----------------------------------------------------------------------------
# Development and execution
# -----------------------------------------------------------------------------
frontend-dev:
	cd $(FRONTEND_DIR) && $(NPM) run dev

run:
	$(GO) run $(GOFLAGS) ./$(CMD_DIR) $(ARGS)

run-web:
	$(GO) run $(GOFLAGS) ./$(CMD_DIR) -web -port 8080

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html

clean-all: clean
	rm -rf $(GEOIP_DIR)/*.mmdb

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help:
	@echo "TraceSleuth v$(VERSION) - Build Targets"
	@echo ""
	@echo "  Build:"
	@echo "    make build            Build frontend and embedded Go binary"
	@echo "    make build-frontend   Build React frontend only"
	@echo "    make build-backend    Build Go binary only"
	@echo "    make build-all        Cross-compile Linux, macOS, and Windows"
	@echo "    make release          Create release archives and checksums"
	@echo "    make install          Install current command package"
	@echo ""
	@echo "  Test and quality:"
	@echo "    make test             Run Go tests"
	@echo "    make test-coverage    Generate Go coverage report"
	@echo "    make test-race        Run Go race detector"
	@echo "    make fmt-check        Verify gofmt cleanliness"
	@echo "    make vet              Run go vet"
	@echo "    make lint             Run formatting and vet checks"
	@echo "    make check-version    Validate bootstrap version contract"
	@echo ""
	@echo "  Run:"
	@echo "    make run ARGS='...'   Run CLI mode"
	@echo "    make run-web          Run local web mode"
	@echo "    make frontend-dev     Start frontend development server"
	@echo ""
	@echo "  Clean:"
	@echo "    make clean            Remove build artifacts"
	@echo "    make clean-all        Also remove GeoIP data"
	@echo ""
	@echo "  Version: $(VERSION) | Commit: $(COMMIT) | Date: $(DATE)"
