# syntax=docker/dockerfile:1

# Reproducible builds: set SOURCE_DATE_EPOCH to clamp file timestamps.
# Pass --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) at build time.
ARG SOURCE_DATE_EPOCH=0

# --- Frontend build ---
FROM node:22-bookworm-slim@sha256:7af03b14a13c8cdd38e45058fd957bf00a72bbe17feac43b1c15a689c029c732 AS ui-build
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

WORKDIR /app/site
COPY site/package.json site/package-lock.json* ./
RUN npm ci
COPY site/ ./
RUN npm run build
# Output goes to /app/internal/ui/dist

# --- Go build ---
FROM golang:1.26-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS go-build
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=1970-01-01T00:00:00Z

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=ui-build /app/internal/ui/dist ./internal/ui/dist

# Build CLI binaries for all platforms (reproducible)
RUN <<EOF
	LDFLAGS="-X github.com/hibouhq/lehibou/internal/version.Version=${VERSION} \
			 -X github.com/hibouhq/lehibou/internal/version.Commit=${COMMIT} \
			 -X github.com/hibouhq/lehibou/internal/version.Date=${DATE}"
	mkdir -p /out/bin
	for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
		os="${platform%/*}"
		arch="${platform#*/}"
		ext=""
		if [ "$os" = "windows" ]; then ext=".exe"; fi
		CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
			go build -buildvcs=false -trimpath -ldflags "$LDFLAGS" \
			-o "/out/bin/hibou-${os}-${arch}${ext}" .
	done
	# Symlink for argv[0] server personality (copied via directory COPY to preserve it)
	mkdir -p /out/symlinks
	ln -s /usr/local/bin/hibou-bin/hibou-${TARGETOS}-${TARGETARCH} /out/symlinks/hibou-server
EOF

# --- Runtime (Wolfi-based, reproducible, 0 CVE) ---
# Built from apko.yaml using: apko build apko.yaml hibou-base:latest hibou-base.tar
# Lock file (apko.lock.json) pins exact package versions for reproducibility.
# To update: apko lock apko.yaml && apko build --lockfile apko.lock.json apko.yaml ...
FROM hibou-base:latest-amd64 AS runtime-amd64
FROM hibou-base:latest-arm64 AS runtime-arm64
FROM runtime-${TARGETARCH}

COPY --from=go-build /out/bin/ /usr/local/bin/hibou-bin/
COPY --from=go-build /out/symlinks/ /usr/local/bin/

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hibou-server"]
CMD ["serve"]
