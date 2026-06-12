# syntax=docker/dockerfile:1

# Slim runtime image: copies pre-built binaries from build context.
# Build binaries first with: make build-all
# Build base image first with: make base-image
#
# Reproducible builds: pass --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

ARG SOURCE_DATE_EPOCH=0
ARG TARGETARCH
ARG BASE_IMAGE=hibou-base:latest

# --- Runtime (Wolfi-based, reproducible, 0 CVE) ---
# Built from apko.yaml. CI publishes a multi-arch base image and passes BASE_IMAGE.
# Lock file (apko.lock.json) pins exact package versions for reproducibility.
# To update: apko lock apko.yaml.
FROM ${BASE_IMAGE} AS runtime

FROM busybox:stable AS prep
ARG TARGETARCH
COPY dist/hibou-* /out/
RUN cp "/out/hibou-linux-${TARGETARCH}" /out/hibou \
	&& ln -s hibou /out/hibou-server

FROM runtime

COPY --from=prep /out/ /usr/local/bin/

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hibou-server"]
CMD ["serve"]
