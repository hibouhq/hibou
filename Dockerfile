# syntax=docker/dockerfile:1

# Slim runtime image: copies pre-built binaries from build context.
# Build binaries first with: make build-image-binaries (main) or make build-all (release)
# Build base image first with: make base-image
#
# Reproducible builds: pass --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

ARG SOURCE_DATE_EPOCH=0
ARG TARGETARCH
ARG BASE_IMAGE=hibou-base:latest
ARG INCLUDE_EXTRA_CLI_BINARIES=false

# --- Runtime (Wolfi-based, reproducible, 0 CVE) ---
# Built from apko.yaml. CI publishes a multi-arch base image and passes BASE_IMAGE.
# Lock file (apko.lock.json) pins exact package versions for reproducibility.
# To update: apko lock apko.yaml.
FROM ${BASE_IMAGE} AS runtime

FROM busybox:stable AS prep
ARG TARGETARCH

ARG INCLUDE_EXTRA_CLI_BINARIES
COPY dist/hibou-* /staged/
# Assemble exactly what ships in /usr/local/bin:
#   - hibou / hibou-server: this image's native (linux/$TARGETARCH) binary + entrypoint alias
#   - hibou-<os>-<arch>: every release CLI binary, served by GET /api/v1/bin/{os}/{arch}
#     so clients (e.g. the hibou-upload CI action) can self-download a version-matched CLI.
RUN set -eux; \
	mkdir -p /out; \
	for f in hibou-linux-amd64 hibou-linux-arm64; do \
		install -m 0555 "/staged/$f" "/out/$f"; \
	done; \
	if [ "${INCLUDE_EXTRA_CLI_BINARIES}" = 'true' ]; then \
		for f in hibou-darwin-arm64 hibou-windows-amd64.exe hibou-windows-arm64.exe; do \
			install -m 0555 "/staged/$f" "/out/$f"; \
		done; \
	fi; \
	install -m 0555 "/staged/hibou-linux-${TARGETARCH}" /out/hibou; \
	ln -sf hibou /out/hibou-server

FROM runtime

COPY --from=prep /out/ /usr/local/bin/

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hibou-server"]
CMD ["serve"]
