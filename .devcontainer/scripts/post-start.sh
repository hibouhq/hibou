#!/bin/bash

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/lib.sh"

main(){
	start_dockerd
	log_info "All done ! 🚀"
}

if ! _is_sourced; then
	set -euo pipefail

	cd "$(dirname "$0")"
	main "$@"
fi
