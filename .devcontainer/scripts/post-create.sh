#!/bin/bash

set -euo pipefail

main(){
#   "postCreateCommand": " && cd site && npm install && playwright-cli install --skills",
    go mod download
    go install github.com/go-delve/delve/cmd/dlv@latest
    go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
    go install github.com/swaggo/swag/cmd/swag@v1.16.6
    sudo npm install -g @playwright/cli@latest
    playwright-cli --version
}

main "$@"
