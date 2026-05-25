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
up: ## Start Docker Compose services (postgres only by default)
	docker compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@until docker compose exec -T postgres pg_isready -U hibou -d hibou >/dev/null 2>&1; do sleep 1; done
	@echo "PostgreSQL is ready."

.PHONY: up-all
up-all: ## Start all Docker Compose services (postgres, forgejo, trivy)
	docker compose up -d
	@echo "All services started."

.PHONY: down
down: ## Stop Docker Compose services
	docker compose down

.PHONY: setup
setup: up ## Quick dev setup: start postgres + seed sample data
	@echo "==> Running migrations and seeding data..."
	go run . seed
	@echo ""
	@echo "==> Setup complete! Run 'make dev' to start the app."
	@echo "    Then open http://localhost:3000 and click 'Dev Login'."

.PHONY: setup-full
setup-full: up-all ## Full setup with Forgejo OAuth (for OAuth testing)
	@./scripts/setup-dev.sh

.PHONY: fix-auth
fix-auth: ## Fix OAuth redirect for VS Code port forwarding (PORT=<forwarded_port>)
	@./scripts/fix-oauth-port.sh $(PORT)

.PHONY: start
start: setup-full ## One command: full setup with real data + start the app
	@./scripts/seed-real.sh
	@$(MAKE) dev

.PHONY: start-quick
start-quick: setup ## Quick start with fake seed data
	@$(MAKE) dev

.PHONY: seed
seed: ## Re-seed the database with sample data
	go run . seed

.PHONY: reset
reset: ## Reset database and re-seed
	docker compose exec -T postgres psql -U hibou -d hibou -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION IF NOT EXISTS pgcrypto;"
	go run . seed
	@echo "Database reset and reseeded."

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

.PHONY: install
install: build ## Install hibou binary and create hibou-server symlink
	install -m 755 $(DIST)/$(BINARY) $(shell go env GOPATH)/bin/$(BINARY)
	ln -sf $(BINARY) $(shell go env GOPATH)/bin/hibou-server

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
		set -a; [ -f .env ] && . ./.env; set +a; \
		HIBOU_ARTIFACT_PATH=tmp/artifacts go run . serve & \
		cd $(FRONTEND) && npx vite --host 0.0.0.0 & \
		wait

.PHONY: db-migrate
db-migrate: ## Database migrations run automatically on hibou-server serve startup
	@echo "Migrations run automatically on 'hibou-server serve'. Set HIBOU_DATABASE_URL as needed and start the server."


.PHONY: generate
generate: ## Run code generation (sqlc, swagger)
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
