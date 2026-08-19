BINARY    := hibou
DIST      := dist
FRONTEND  := site

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE      := $(shell git log -1 --format=%cI 2>/dev/null || echo 1970-01-01T00:00:00Z)

LDFLAGS   := -X github.com/hibouhq/hibou/internal/version.Version=$(VERSION) \
			 -X github.com/hibouhq/hibou/internal/version.Commit=$(COMMIT) \
			 -X github.com/hibouhq/hibou/internal/version.Date=$(DATE)
GO_BUILD_FLAGS := -buildvcs=false -trimpath
SQLC      := $(if $(wildcard /usr/local/bin/sqlc),/usr/local/bin/sqlc,sqlc)

# Build targets regenerate by default so a local `make build-all` never ships
# stale sqlc/swagger output. CI overrides this with GENERATE_DEP= because its
# Prepare step already ran check-generate, and re-running `generate` in a
# parallel step rewrites dbgen/ in place while `make lint` (sqlc diff) and
# gosec are reading it — a race that intermittently fails the Lint step.
GENERATE_DEP ?= generate
SWAG      := $(if $(wildcard /usr/local/bin/swag),/usr/local/bin/swag,swag)

# Reproducible release build (callers append: -o <out> .)
# -tags withui embeds the built SPA (internal/ui). Only shipped binaries use
# GO_BUILD and they all run `build-frontend` first; dev/test/lint build without
# the tag and get the no-SPA stub (internal/ui/embed_stub.go), so they don't
# need a frontend build to compile.
GO_BUILD  := CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -tags withui -ldflags '$(LDFLAGS)'
# psql inside the dev postgres container
PSQL      := docker compose exec -T postgres psql -U hibou -d hibou
# Dedicated test database — keeps integration tests out of the dev database.
TEST_DB       := hibou_test
TEST_DATABASE_URL := postgres://hibou:hibou@localhost:5432/$(TEST_DB)?sslmode=disable

# Build targets: linux/amd64, linux/arm64, windows/amd64, windows/arm64, darwin/arm64
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/arm64
IMAGE_PLATFORMS := linux/amd64 linux/arm64

.PHONY: all
all: generate lint test build ## Default: generate, lint, test, build

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
setup: up dev-bin ## Quick dev setup: start postgres + seed sample data
	@echo "==> Running migrations and seeding data..."
	tmp/dev/hibou-server seed
	@echo ""
	@echo "==> Setup complete! Run 'make dev' to start the app."
	@echo "    Then open http://localhost:3000 and click 'Dev Login'."

.PHONY: setup-full
setup-full: up-all ## Full setup with Forgejo OAuth (for OAuth testing)
	@./scripts/setup-dev.sh

.PHONY: start
start: export HIBOU_DEVELOPMENT = true
start: setup-full build-frontend ## One command: full setup with real data + start the app
	@./scripts/seed-real.sh
	@$(MAKE) dev

.PHONY: start-quick
start-quick: export HIBOU_DEVELOPMENT = true
start-quick: setup build-frontend ## Quick start with fake seed data
	@$(MAKE) dev

.PHONY: seed
seed: dev-bin ## Re-seed the database with sample data
	tmp/dev/hibou-server seed

.PHONY: reset
reset: dev-bin ## Reset database and re-seed
	$(PSQL) -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION IF NOT EXISTS pgcrypto;"
	tmp/dev/hibou-server seed
	@echo "Database reset and reseeded."

.PHONY: lint
lint: ## Run linters (CI gate: fails on any warning)
	sqlc diff
	golangci-lint run ./...
	cd $(FRONTEND) && npx eslint . --max-warnings=0

.PHONY: lint-fix
lint-fix: ## Auto-fix lint issues (Go + frontend) before committing
	golangci-lint run --fix ./...
	cd $(FRONTEND) && npx eslint . --fix --max-warnings=0

.PHONY: test-db
test-db: ## Create a pristine test database (drops + recreates $(TEST_DB))
	@docker compose exec -T postgres psql -U hibou -d postgres -v ON_ERROR_STOP=1 \
		-c "DROP DATABASE IF EXISTS $(TEST_DB) WITH (FORCE)" \
		-c "CREATE DATABASE $(TEST_DB)" >/dev/null 2>&1 \
		&& echo "Test database $(TEST_DB) ready." \
		|| echo "WARN: postgres not reachable via docker compose — Go integration tests will skip."

.PHONY: test
test: test-db ## Run Go and frontend tests (Go tests use $(TEST_DB), not the dev db)
	HIBOU_DATABASE_URL='$(TEST_DATABASE_URL)' go test -race -count=1 ./...
	cd $(FRONTEND) && npx vitest run

.PHONY: coverage
coverage: test-db ## Run Go tests with coverage + JUnit report (uses $(TEST_DB))
	@if command -v gotestsum >/dev/null 2>&1; then \
		HIBOU_DATABASE_URL='$(TEST_DATABASE_URL)' gotestsum --junitfile junit-go.xml --format pkgname \
			-- -count=1 -coverprofile=coverage.out ./internal/...; \
	else \
		echo "gotestsum not found; running plain go test (no JUnit report)"; \
		HIBOU_DATABASE_URL='$(TEST_DATABASE_URL)' go test -count=1 -coverprofile=coverage.out ./internal/...; \
	fi
	go tool cover -func=coverage.out | tail -1
	@echo "HTML report: go tool cover -html=coverage.out"

.PHONY: build-frontend
build-frontend: ## Build the Vue SPA
	cd $(FRONTEND) && npm run build
	# Output: internal/ui/dist/

.PHONY: build
build: generate build-frontend ## Build the hibou binary for the current platform
	mkdir -p $(DIST)
	$(GO_BUILD) -o $(DIST)/$(BINARY) .

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
	 $(GO_BUILD) -o /tmp/hibou-repro .; \
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
		--build-arg BASE_IMAGE=hibou-base:latest-$$(go env GOARCH) \
		-t ghcr.io/hibouhq/hibou:$(VERSION) .

.PHONY: check-reproducible-image
check-reproducible-image: build-all base-image ## Verify Docker image reproducibility (builds twice without cache, compares digests)
	@echo "==> Building image twice (no cache) to verify reproducibility..."
	@docker build --no-cache -q \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		--build-arg BASE_IMAGE=hibou-base:latest-$$(go env GOARCH) \
		-t hibou-repro-1 . > /dev/null
	@docker build --no-cache -q \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		--build-arg BASE_IMAGE=hibou-base:latest-$$(go env GOARCH) \
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
build-all: $(GENERATE_DEP) build-frontend ## Cross-compile for all target platforms
	@mkdir -p $(DIST); \
	pids=""; fail=0; \
	for platform in $(PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		ext=; [ "$$goos" = "windows" ] && ext=.exe; \
		( GOOS=$$goos GOARCH=$$goarch $(GO_BUILD) \
			-o $(DIST)/$(BINARY)-$$goos-$$goarch$$ext . && \
		  if [ "$$goos" = "linux" ]; then \
			ln -sf $(BINARY)-$$goos-$$goarch$$ext $(DIST)/$(BINARY)-server-$$goarch; \
		  fi ) & pids="$$pids $$!"; \
	done; \
	for pid in $$pids; do wait $$pid || fail=1; done; \
	[ $$fail -eq 0 ]

.PHONY: build-image-binaries
build-image-binaries: $(GENERATE_DEP) build-frontend ## Cross-compile only the Linux binaries needed by container image builds
	@mkdir -p $(DIST); \
	pids=""; fail=0; \
	for platform in $(IMAGE_PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		( GOOS=$$goos GOARCH=$$goarch $(GO_BUILD) \
			-o $(DIST)/$(BINARY)-$$goos-$$goarch . && \
		  ln -sf $(BINARY)-$$goos-$$goarch $(DIST)/$(BINARY)-server-$$goarch ) & pids="$$pids $$!"; \
	done; \
	for pid in $$pids; do wait $$pid || fail=1; done; \
	[ $$fail -eq 0 ]

.PHONY: build-all-ci
build-all-ci: $(GENERATE_DEP) ## Cross-compile all release binaries, assuming frontend dist is already prepared
	@mkdir -p $(DIST); \
	pids=""; fail=0; \
	for platform in $(PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		ext=; [ "$$goos" = "windows" ] && ext=.exe; \
		( GOOS=$$goos GOARCH=$$goarch $(GO_BUILD) \
			-o $(DIST)/$(BINARY)-$$goos-$$goarch$$ext . && \
		  if [ "$$goos" = "linux" ]; then \
			ln -sf $(BINARY)-$$goos-$$goarch$$ext $(DIST)/$(BINARY)-server-$$goarch; \
		  fi ) & pids="$$pids $$!"; \
	done; \
	for pid in $$pids; do wait $$pid || fail=1; done; \
	[ $$fail -eq 0 ]

.PHONY: build-image-binaries-ci
build-image-binaries-ci: $(GENERATE_DEP) ## Cross-compile only Linux image binaries, assuming frontend dist is already prepared
	@mkdir -p $(DIST); \
	pids=""; fail=0; \
	for platform in $(IMAGE_PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		( GOOS=$$goos GOARCH=$$goarch $(GO_BUILD) \
			-o $(DIST)/$(BINARY)-$$goos-$$goarch . && \
		  ln -sf $(BINARY)-$$goos-$$goarch $(DIST)/$(BINARY)-server-$$goarch ) & pids="$$pids $$!"; \
	done; \
	for pid in $$pids; do wait $$pid || fail=1; done; \
	[ $$fail -eq 0 ]

.PHONY: dev-bin
dev-bin: ## Build dev binary + hibou-server symlink (tmp/dev)
	@mkdir -p tmp/dev
	go build $(GO_BUILD_FLAGS) -o tmp/dev/$(BINARY) .
	@ln -sf $(BINARY) tmp/dev/hibou-server

.PHONY: dev
dev: dev-bin ## Run backend + Vite dev server concurrently
	@trap 'kill 0' EXIT; \
		set -a; [ -f .env ] && . ./.env; set +a; \
		HIBOU_DEVELOPMENT=true HIBOU_ARTIFACT_PATH=tmp/artifacts tmp/dev/hibou-server serve & \
		cd $(FRONTEND) && npx vite --host 0.0.0.0 & \
		wait

.PHONY: db-migrate
db-migrate: ## Database migrations run automatically on hibou-server serve startup
	@echo "Migrations run automatically on 'hibou-server serve'. Set HIBOU_DATABASE_URL as needed and start the server."


.PHONY: generate
generate: ## Run code generation (sqlc, swagger)
	$(SQLC) generate
	$(SWAG) init --parseDependency --parseInternal -g main.go -o internal/apidoc

.PHONY: check-generate
check-generate: generate ## Fail if generated files are not up to date
	@git diff --exit-code || (echo "Generated files are stale. Run 'make generate' and commit the result."; exit 1)

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
