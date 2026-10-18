#!/usr/bin/env bash
# Writes the devcontainer's pinned Node version to $GITHUB_OUTPUT as
# `version`, so Renovate keeps one source of truth.
set -euo pipefail

version="$(sed -nE "s/^ARG NODE_VERSION='([0-9.]+)'$/\1/p" .devcontainer/Dockerfile)"
if [[ -z "${version}" ]]; then
  echo "::error::NODE_VERSION not found in .devcontainer/Dockerfile"
  exit 1
fi
echo "version=${version}" >> "${GITHUB_OUTPUT}"
