#!/usr/bin/env bash
# Removes large pre-installed packages from GitHub-hosted runners to free ~15GB.
set -euo pipefail

echo "Freeing disk space on GitHub-hosted runner..."

before=$(df / | awk 'NR==2 {print $3}')

sudo rm -rf /usr/local/lib/android &
sudo rm -rf /usr/share/dotnet &
sudo rm -rf /opt/ghc &
sudo rm -rf /usr/local/.ghcup &
sudo rm -rf /usr/share/swift &
sudo rm -rf /usr/local/share/boost &
wait

after=$(df / | awk 'NR==2 {print $3}')
avail=$(df -h / | awk 'NR==2 {print $4}')
saved=$(( (before - after) / 1024 / 1024 ))
echo "Freed: ${saved}GB — Available: ${avail}"
