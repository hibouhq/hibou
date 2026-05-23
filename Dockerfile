# syntax=docker/dockerfile:1

# --- Frontend build ---
FROM node:22-bookworm-slim AS ui-build
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

WORKDIR /app/site
COPY site/package.json site/package-lock.json* ./
RUN npm ci
COPY site/ ./
RUN npm run build

# --- Go build ---
FROM golang:1.23-bookworm AS go-build
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
COPY --from=ui-build /app/dist/site ./dist/site

RUN <<EOF
	CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
	go build \
	-buildvcs=false \
		-ldflags "-X github.com/hibouhq/lehibou/internal/version.Version=${VERSION} \
				  -X github.com/hibouhq/lehibou/internal/version.Commit=${COMMIT} \
				  -X github.com/hibouhq/lehibou/internal/version.Date=${DATE}" \
		-o /out/hibou .
EOF

# --- Runtime ---
FROM gcr.io/distroless/base-debian12

COPY --from=go-build /out/hibou /usr/local/bin/hibou
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hibou"]
CMD ["serve"]