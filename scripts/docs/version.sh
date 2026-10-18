#!/usr/bin/env bash
# Decides which docs version a run publishes and writes `version` and
# `is_latest` to $GITHUB_OUTPUT.
#   tag vX.Y.Z     -> vX.Y (and "stable" is refreshed)
#   manual version -> that version (sanitized)
#   otherwise      -> latest
# Inputs (env): REF_TYPE, REF_NAME, INPUT_VERSION.
set -euo pipefail

if [[ "${REF_TYPE:-}" == "tag" ]]; then
  if [[ ! "${REF_NAME}" =~ ^v[0-9]+\.[0-9]+ ]]; then
    echo "::error::Unexpected tag name: ${REF_NAME}"
    exit 1
  fi
  version="$(echo "${REF_NAME}" | sed -E 's/^(v[0-9]+\.[0-9]+).*/\1/')"
  is_latest=false
elif [[ -n "${INPUT_VERSION:-}" && "${INPUT_VERSION}" != "latest" ]]; then
  # Sanitize: only allow semver-like patterns (v1.0, v1.0.0, etc.)
  if [[ ! "${INPUT_VERSION}" =~ ^v?[0-9]+(\.[0-9]+){0,2}$ ]]; then
    echo "::error::Invalid version format: ${INPUT_VERSION}"
    exit 1
  fi
  version="${INPUT_VERSION}"
  is_latest=false
else
  version=latest
  is_latest=true
fi

echo "version=${version}" >> "${GITHUB_OUTPUT}"
echo "is_latest=${is_latest}" >> "${GITHUB_OUTPUT}"
