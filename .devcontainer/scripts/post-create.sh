#!/bin/bash

set -euo pipefail

main(){
    go mod download
}

main "$@"
