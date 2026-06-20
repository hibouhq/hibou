#!/bin/bash

set -euo pipefail # Enforce new scripts to be written using defensive programming

# Library of helper functions for other scripts

# Internal function
__BOLD="\e[1m";__RESET="\e[0m";__RED="\e[91m";__GREEN="\e[92m";__YELLOW="\e[93m";__CYAN="\e[96m";
_logging(){
	local type=$1; shift
	local dt=; dt="$(date -Iseconds)"
	local script_name=; script_name="$(basename "$0")"
	printf "%s ${__CYAN}${__BOLD}${script_name}${__RESET} [%b] : %b\n" "$dt" "$type" "$*"
}

log_info() {
	_logging "${__GREEN}info${__RESET}" "$@"
}

log_warn(){
	_logging "${__YELLOW}warn${__RESET}" "$@"
}

log_error() {
	_logging "${__RED}error${__RESET}" "$@" >&2;
	exit 2
}

log_error_no_exit() {
	_logging "${__RED}error${__RESET}" "$@" >&2;
}

disable_colors(){
	export __BOLD='' __RESET='' __RED='' __GREEN='' __YELLOW='' __CYAN=''
}

check_dependencies() {
	local missing=false
		for command in "$@"; do
		if ! command -v "$command" &> /dev/null; then
			log_error_no_exit "Command '$command' not found in PATH but required by '$(basename "$0")'." >&2
			missing=true
		fi
	done

	if [ "$missing" = true ]; then
		exit 1
	fi
}

_is_sourced() {
	[ "${#FUNCNAME[@]}" -ge 2 ] \
		&& [ "${FUNCNAME[0]}" = '_is_sourced' ] \
		&& [ "${FUNCNAME[1]}" = 'source' ]
}

######################
# Devcontainer feature #
######################

start_dockerd(){
	# Start dockerd (installed in Dockerfile via docker-in-docker install.sh)
	if [ -f /usr/local/share/docker-init.sh ] && ! docker info >/dev/null 2>&1; then
		log_info "Starting Docker daemon..."
		if ! sudo /usr/local/share/docker-init.sh; then
			log_error "Docker init failed. Check /tmp/dockerd.log and /tmp/containerd.log."
		fi

		if ! docker info >/dev/null 2>&1; then
			log_error "Docker daemon is still unavailable after docker-init completed. Check /tmp/dockerd.log and /tmp/containerd.log."
		fi
	fi
}
