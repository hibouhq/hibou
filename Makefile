BINARY    := hibou
DIST      := dist
FRONTEND  := site

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      := $(shell git log -1 --format=%cI 2>/dev/null || echo 1970-01-01T00:00:00Z)

LDFLAGS   := -X github.com/hibouhq/lehibou/internal/version.Version=$(VERSION) \
             -X github.com/hibouhq/lehibou/internal/version.Commit=$(COMMIT) \
             -X github.com/hibouhq/lehibou/internal/version.Date=$(DATE)
GO_BUILD_FLAGS := -buildvcs=false -trimpath

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

.PHONY: start
start: setup-full build-frontend ## One command: full setup with real data + start the app
	@./scripts/seed-real.sh
	@$(MAKE) dev

.PHONY: start-quick
start-quick: setup build-frontend ## Quick start with fake seed data
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

.PHONY: coverage
coverage: ## Run Go tests with coverage report
	go test -race -count=1 -coverprofile=coverage.out ./internal/...
	go tool cover -func=coverage.out | tail -1
	@echo "HTML report: go tool cover -html=coverage.out"

.PHONY: build-frontend
build-frontend: ## Build the Vue SPA
	cd $(FRONTEND) && npm run build
	# Output: internal/ui/dist/

.PHONY: build
build: build-frontend ## Build the hibou binary for the current platform
	mkdir -p $(DIST)
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BINARY) .

.PHONY: check-reproducible
check-reproducible: ## Verify build reproducibility (rebuilds frontend + Go binary, compares with dist/)
	@REPRO_BIN=$(DIST)/$(BINARY)-$$(go env GOOS)-$$(go env GOARCH); \
	 if [ ! -f "$$REPRO_BIN" ]; then \
	   REPRO_BIN=$(DIST)/$(BINARY); \
	   if [ ! -f "$$REPRO_BIN" ]; then echo "==> FAIL: run 'make build' or 'make build-all' first"; exit 1; fi; \
	 fi; \
	 echo "==> Rebuilding frontend..."; \
	 cd $(FRONTEND) && npm run build > /dev/null 2>&1 && cd ..; \
	 echo "==> Rebuilding Go binary..."; \
	 CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o /tmp/hibou-repro .; \
	 hash1=$$(sha256sum "$$REPRO_BIN" | cut -d' ' -f1); \
	 hash2=$$(sha256sum /tmp/hibou-repro | cut -d' ' -f1); \
	 rm -f /tmp/hibou-repro; \
	 if [ "$$hash1" = "$$hash2" ]; then \
	   echo "==> Reproducible: $$hash1"; \
	 else \
	   echo "==> FAIL: original: $$hash1"; \
	   echo "==>       rebuild:  $$hash2"; \
	   exit 1; \
	 fi

SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct 2>/dev/null || echo 0)

.PHONY: base-image
base-image: ## Build Wolfi base image from apko.yaml (locked)
	@echo "==> Building Wolfi base image from apko.yaml..."
	apko build $(if $(wildcard apko.lock.json),--lockfile apko.lock.json )apko.yaml hibou-base:latest /tmp/hibou-base.tar
	docker load < /tmp/hibou-base.tar
	@echo "==> Base image ready: hibou-base:latest-{amd64,arm64}"

.PHONY: base-image-lock
base-image-lock: ## Resolve and lock Wolfi package versions
	apko lock apko.yaml
	@echo "==> Lock file written: apko.lock.json"

.PHONY: docker-build
docker-build: build-all base-image ## Build reproducible Docker image
	docker build \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		-t ghcr.io/hibouhq/lehibou:$(VERSION) .

.PHONY: check-reproducible-image
check-reproducible-image: build-all base-image ## Verify Docker image reproducibility (builds twice without cache, compares digests)
	@echo "==> Building image twice (no cache) to verify reproducibility..."
	@docker build --no-cache -q \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		-t hibou-repro-1 . > /dev/null
	@docker build --no-cache -q \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		-t hibou-repro-2 . > /dev/null
	@id1=$$(docker inspect --format='{{.Id}}' hibou-repro-1); \
	 id2=$$(docker inspect --format='{{.Id}}' hibou-repro-2); \
	 docker rmi hibou-repro-1 hibou-repro-2 > /dev/null 2>&1; \
	 if [ "$$id1" = "$$id2" ]; then \
	   echo "==> Reproducible image: $$id1"; \
	 else \
	   echo "==> FAIL: build 1: $$id1"; \
	   echo "==>       build 2: $$id2"; \
	   exit 1; \
	 fi

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

.PHONY: k8s-dev
k8s-dev: ## Deploy Hibou to a local kind cluster (with CNPG)
	@bash scripts/k8s-dev.sh

.PHONY: k8s-dev-clean
k8s-dev-clean: ## Tear down the local kind cluster
	@bash scripts/k8s-dev-cleanup.sh
