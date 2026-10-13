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
# renovate: datasource=github-releases depName=betterleaks/betterleaks extractVersion=^v(?<version>.+)$
ARG BETTERLEAKS_VERSION=1.7.1
# SHA-256 of the linux release archives for BETTERLEAKS_VERSION, from the
# release's checksums.txt (cross-checked against the GitHub asset digests).
# A version bump without updating both fails the build instead of trusting a
# checksum fetched next to the archive.
ARG BETTERLEAKS_SHA256_AMD64=48d9ae267b46677c9943cf9291bed682ed7b37b5b2c6ffbdea47a155495e5dcc
ARG BETTERLEAKS_SHA256_ARM64=c350f1c94c7187f81a8900aa17b50ee868fdc72e89dac849d68d757754665721

# --- Runtime (Wolfi-based, reproducible, 0 CVE) ---
# Built from apko.yaml. CI publishes a multi-arch base image and passes BASE_IMAGE.
# Lock file (apko.lock.json) pins exact package versions for reproducibility.
# To update: apko lock apko.yaml.
FROM ${BASE_IMAGE} AS runtime

# betterleaks is not packaged in wolfi (unlike gitleaks, which comes from
# apko.yaml), so it ships from its GitHub release, verified against the
# per-arch SHA-256 pinned above. It needs no shell at runtime (pure go-git),
# which is why it — and not trufflehog — is the verification engine we ship.
# Checksum-verified content keeps the layer stable across rebuilds despite the
# network fetch.
# Pinned to the multi-arch index digest; Renovate keeps the tag and digest current.
FROM alpine:3@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS betterleaks
ARG TARGETARCH
ARG BETTERLEAKS_VERSION
ARG BETTERLEAKS_SHA256_AMD64
ARG BETTERLEAKS_SHA256_ARM64
RUN set -eux; \
	apk add --no-cache curl; \
	case "${TARGETARCH}" in \
		amd64) arch=x64; sum="${BETTERLEAKS_SHA256_AMD64}" ;; \
		arm64) arch=arm64; sum="${BETTERLEAKS_SHA256_ARM64}" ;; \
		*) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
	esac; \
	asset="betterleaks_${BETTERLEAKS_VERSION}_linux_${arch}.tar.gz"; \
	curl -fsSLO "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/${asset}"; \
	echo "${sum}  ${asset}" | sha256sum -c -; \
	tar -xzf "${asset}" -C /usr/local/bin betterleaks; \
	/usr/local/bin/betterleaks version

# Pinned to the multi-arch index digest; Renovate keeps the tag and digest current.
FROM busybox:stable@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662 AS prep
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

LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=prep /out/ /usr/local/bin/
COPY --from=betterleaks /usr/local/bin/betterleaks /usr/local/bin/betterleaks

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hibou-server"]
CMD ["serve"]
