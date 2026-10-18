#!/usr/bin/env bash
# Builds the docs site for one version into docs/dist.
# Inputs (env): DOCS_VERSION. It arrives as data, never as interpolated
# script text.
set -euo pipefail

cd docs
npm ci
DOCS_BASE="/${DOCS_VERSION}" \
PUBLIC_DOCS_VERSION="${DOCS_VERSION}" \
npm run build
