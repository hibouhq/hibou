BINARY    := hibou
DIST      := dist
FRONTEND  := site

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS   := -X github.com/hibouhq/lehibou/internal/version.Version=$(VERSION) \
             -X github.com/hibouhq/lehibou/internal/version.Commit=$(COMMIT) \
             -X github.com/hibouhq/lehibou/internal/version.Date=$(DATE)
GO_BUILD_FLAGS := -buildvcs=false

# Build targets: linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/arm64
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/arm64

.PHONY: all lint test build build-all build-frontend dev clean help

all: lint test build ## Default: lint, test, build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

lint: ## Run Go and frontend linters
	golangci-lint run ./...
	cd $(FRONTEND) && npx eslint . --max-warnings=0

test: ## Run Go and frontend tests
	go test -race -count=1 ./...
	cd $(FRONTEND) && npx vitest run

build-frontend: ## Build the Vue SPA
	cd $(FRONTEND) && npm run build

build: build-frontend ## Build the hibou binary for the current platform
	mkdir -p $(DIST)
	go build $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) .

build-all: build-frontend ## Cross-compile for all target platforms
	$(foreach platform,$(PLATFORMS),\
		$(eval GOOS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval GOARCH := $(word 2,$(subst /, ,$(platform)))) \
		$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,)) \
		mkdir -p $(DIST) && \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
			go build $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT) . && \
	) true

dev: ## Run backend + Vite dev server concurrently
	@trap 'kill 0' EXIT; \
		go run github.com/air-verse/air@latest & \
		cd $(FRONTEND) && npx vite --host 0.0.0.0 & \
		wait

db-migrate: ## Run database migrations (placeholder)
	@echo "TODO: wire database migrations"

generate: ## Run code generation (placeholder)
	@echo "TODO: wire sqlc and other generators"

clean: ## Remove build artifacts
	rm -rf $(DIST)
