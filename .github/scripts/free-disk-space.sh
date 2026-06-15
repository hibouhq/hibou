#!/usr/bin/env bash
# Removes large pre-installed packages from GitHub-hosted runners to free ~15GB.
set -euo pipefail

before=$(df / | awk 'NR==2 {print $3}')

sudo rm -rf \
  /usr/local/lib/android \
  /usr/share/dotnet \
  /opt/ghc \
  /usr/local/.ghcup \
  /usr/share/swift \
  /usr/local/share/boost

after=$(df / | awk 'NR==2 {print $3}')
avail=$(df -h / | awk 'NR==2 {print $4}')
saved=$(( (before - after) / 1024 / 1024 ))
echo "Freed: ${saved}GB — Available: ${avail}"
