# syntax=docker/dockerfile:1

# Slim runtime image: copies pre-built binaries from build context.
# Build binaries first with: make build-all
# Build base image first with: make base-image
#
# Reproducible builds: pass --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

ARG SOURCE_DATE_EPOCH=0
ARG TARGETARCH

# --- Runtime (Wolfi-based, reproducible, 0 CVE) ---
# Built from apko.yaml using: apko build apko.yaml hibou-base:latest hibou-base.tar
# Lock file (apko.lock.json) pins exact package versions for reproducibility.
# To update: apko lock apko.yaml && apko build --lockfile apko.lock.json apko.yaml ...
FROM hibou-base:latest-amd64 AS runtime-amd64
FROM hibou-base:latest-arm64 AS runtime-arm64

FROM busybox:stable AS prep
ARG TARGETARCH
COPY dist/hibou-linux-${TARGETARCH} /out/hibou
RUN ln -s hibou /out/hibou-server

FROM runtime-${TARGETARCH}

COPY --from=prep /out/ /usr/local/bin/

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hibou-server"]
CMD ["serve"]
