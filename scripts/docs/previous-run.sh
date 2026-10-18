#!/usr/bin/env bash
# Writes the id of the last successful docs run to $GITHUB_OUTPUT as
# `run_id` (empty if none). download-artifact only sees the current run
# unless given a run id, so without this every deploy started from an empty
# site and dropped all other versions. The saved site expires after its
# 90-day retention.
# Inputs (env): GH_TOKEN, GITHUB_REPOSITORY.
set -euo pipefail

run_id="$(gh run list -R "${GITHUB_REPOSITORY}" --workflow docs.yml \
  --status success --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
echo "run_id=${run_id}" >> "${GITHUB_OUTPUT}"
