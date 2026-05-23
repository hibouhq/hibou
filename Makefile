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

.PHONY: all
all: lint test build ## Default: lint, test, build

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: ## Start Docker Compose services (postgres, forgejo, trivy)
	docker compose up -d
	@echo "Services started. Run 'make setup' to configure Forgejo OAuth."

.PHONY: down
down: ## Stop Docker Compose services
	docker compose down

.PHONY: setup
setup: up ## Bootstrap dev environment (Forgejo admin + OAuth app)
	@./scripts/setup-dev.sh

.PHONY: lint
lint: ## Run linters and check generated code
	sqlc diff
	golangci-lint run ./...
	cd $(FRONTEND) && npx eslint . --max-warnings=0

.PHONY: test
test: ## Run Go and frontend tests
	go test -race -count=1 ./...
	cd $(FRONTEND) && npx vitest run

.PHONY: build-frontend
build-frontend: ## Build the Vue SPA
	cd $(FRONTEND) && npm run build
	# Output: internal/ui/dist/

.PHONY: build
build: build-frontend ## Build the hibou binary for the current platform
	mkdir -p $(DIST)
	go build $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) .

.PHONY: build-all
build-all: build-frontend ## Cross-compile for all target platforms
	$(foreach platform,$(PLATFORMS),\
		$(eval GOOS := $(word 1,$(subst /, ,$(platform)))) \
		$(eval GOARCH := $(word 2,$(subst /, ,$(platform)))) \
		$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,)) \
		mkdir -p $(DIST) && \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
			go build $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT) . && \
	) true

.PHONY: dev
dev: ## Run backend + Vite dev server concurrently
	@trap 'kill 0' EXIT; \
		go run github.com/air-verse/air@latest & \
		cd $(FRONTEND) && npx vite --host 0.0.0.0 & \
		wait

.PHONY: db-migrate
db-migrate: ## Database migrations run automatically on hibou serve startup
	@echo "Migrations run automatically on 'hibou serve'. Set HIBOU_DATABASE_URL as needed and start the server."

.PHONY: generate
generate: ## Run code generation
	sqlc generate
	swag init --parseDependency --parseInternal -g main.go -o internal/apidoc

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST)

.PHONY: docs
docs: ## Build the documentation site
	cd docs && DOCS_VERSION=latest DOCS_BASE=/latest npm run build

.PHONY: docs-dev
docs-dev: ## Run documentation dev server
	cd docs && DOCS_VERSION=latest DOCS_BASE=/ npm run dev
