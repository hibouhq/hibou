#!/usr/bin/env bash
# Workaround until github supports parallel steps... (in sept 2026?)
# see https://github.com/github/roadmap/issues/1191
#
# Runs tasks in parallel inside a GitHub Actions step.
# Each task's output is streamed live to stdout (prefixed with the task name)
# so logs are always visible — even on SIGKILL. On failure, a collapsible
# ::group:: block is also printed for each failed task to aid diagnosis.
#
# Usage:
#   parallel-run.sh [--no-fail-fast] <name1> <cmd1> [<name2> <cmd2> ...]
#
# Options:
#   --no-fail-fast   Run all tasks to completion before reporting failures.
#                    Default: stop remaining tasks as soon as one fails.
#
# Arguments:
#   name   Display name shown in GitHub log groups and notices.
#   cmd    Shell command evaluated with `eval`; exported functions are supported.
#
# Exit code:
#   0 if all tasks succeeded, 1 if any task failed.
#
# Env vars:
#   PARALLEL_LOG_DIR          Directory for task log files (default: .github/parallel-logs)
#   PARALLEL_HEARTBEAT_INTERVAL  Seconds between "Still running" notices (default: 45)
#
# Example (fail-fast — stops remaining tasks as soon as one fails):
#   export -f my_exported_function
#   .github/scripts/parallel-run.sh \
#     "Task A"  "./scripts/task-a.sh" \
#     "Task B"  "my_exported_function" \
#     "Task C"  "./scripts/task-c.sh"
#
# Example (no fail-fast — all tasks run to completion regardless of failures):
#   .github/scripts/parallel-run.sh --no-fail-fast \
#     "Task A"  "./scripts/task-a.sh" \
#     "Task B"  "./scripts/task-b.sh"

set -euo pipefail

_cleanup() {
  [[ -n "${_HEARTBEAT_PID-}" ]] && kill "${_HEARTBEAT_PID}" 2>/dev/null || true
  # Print collapsible groups for failed tasks only — live streaming already covered successes
  _print_groups 2>/dev/null || true
}

_parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-fail-fast)
        _FAIL_FAST=false
        shift
        ;;
      *)
        if [[ $# -lt 2 ]]; then
          printf '::error::parallel-run: task "%s" has no command\n' "$1" >&2
          return 1
        fi
        _NAMES+=("$1")
        _CMDS+=("$2")
        shift 2
        ;;
    esac
  done
}

_launch() {
  _TMPDIR="${PARALLEL_LOG_DIR:-.github/parallel-logs}"
  rm -rf "${_TMPDIR}"
  mkdir -p "${_TMPDIR}"
  for i in "${!_NAMES[@]}"; do
    local slug="${_NAMES[$i]// /-}"
    local log="${_TMPDIR}/${i}_${slug}.log"
    _LOGS+=("$log")
    # Stream output live (prefixed) so it survives SIGKILL, and tee to file for group dump on failure.
    # \r is stripped before prefixing so tools that use carriage-return progress output (e.g. Maven/
    # SonarScanner) don't overwrite the prefix and corrupt ::warning::/::error:: workflow commands.
    # Lines that ARE workflow commands (starting with ::) pass through without a prefix so the
    # GitHub Actions runner can process them as annotations.
    (
      set +e +o pipefail
      eval "${_CMDS[$i]}" 2>&1 | tr -d '\r' | tee "$log" \
        | sed -u \
            -e 's/.*QUALITY GATE STATUS: FAILED\(.*\)/::warning::Quality Gate FAILED\1/' \
            -e 's/.*QUALITY GATE STATUS: PASSED\(.*\)/::notice::Quality Gate PASSED\1/' \
            -e "/^::/!s/^/[${_NAMES[$i]}] /"
      echo "${PIPESTATUS[0]}" >"${_TMPDIR}/${i}.rc"
    ) &
    _PIDS+=($!)
    printf 'Started: %s (pid %d)\n' "${_NAMES[$i]}" "${_PIDS[-1]}"
  done
}

# Prints periodic "still running" notices so CI doesn't look stuck.
# PARALLEL_HEARTBEAT_INTERVAL: seconds between notices (default 45)
_start_heartbeat() {
  local heartbeat_interval="${PARALLEL_HEARTBEAT_INTERVAL:-45}"
  local base_sleep=10
  (
    local last_heartbeat=${SECONDS}
    while true; do
      sleep "${base_sleep}"
      local now=${SECONDS}
      if (( now - last_heartbeat >= heartbeat_interval )); then
        last_heartbeat=${now}
        local still_running=()
        for idx in "${!_PIDS[@]}"; do
          if kill -0 "${_PIDS[$idx]}" 2>/dev/null; then
            still_running+=("${_NAMES[$idx]}")
          fi
        done
        if [[ ${#still_running[@]} -gt 0 ]]; then
          local joined
          joined="$(printf '%s, ' "${still_running[@]}")"
          printf '⏳ [%dm%ds] Still running: %s\n' "$((now/60))" "$((now%60))" "${joined%, }"
        fi
      fi
    done
  ) &
  _HEARTBEAT_PID=$!
}

# Waits until all tasks finish.
# Fail-fast: on first failure, kills remaining tasks and stops waiting.
# No-fail-fast: lets all tasks run to completion, collects all failures.
_wait() {
  local -a running=("${!_PIDS[@]}")

  while [[ ${#running[@]} -gt 0 ]]; do
    wait -n 2>/dev/null || true  # block until any child exits; || true absorbs its non-zero rc
    local -a next=()
    for idx in "${running[@]}"; do
      if ! kill -0 "${_PIDS[$idx]}" 2>/dev/null; then
        local rc
        rc=$(cat "${_TMPDIR}/${idx}.rc" 2>/dev/null || echo 1)
        if [[ $rc -ne 0 ]]; then
          _FAILED_NAMES+=("${_NAMES[$idx]}")
          printf '::error::"%s" failed (rc=%d)\n' "${_NAMES[$idx]}" "$rc"
          if [[ "${_FAIL_FAST}" == "true" ]]; then
            for other in "${running[@]}"; do
              [[ "$other" -eq "$idx" ]] && continue
              printf 'Fail-fast: killing "%s" (pid %d)\n' "${_NAMES[$other]}" "${_PIDS[$other]}"
              kill "${_PIDS[$other]}" 2>/dev/null || true
            done
            next=(); break
          fi
        else
          printf 'Completed: %s\n' "${_NAMES[$idx]}"
        fi
      else
        next+=("$idx")
      fi
    done
    running=("${next[@]+"${next[@]}"}")
  done

  # Drain any remaining subshells (e.g. killed ones)
  for pid in "${_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
}

# Prints collapsible groups for failed tasks only.
# Successful tasks don't need a group — their output was already streamed live.
_print_groups() {
  [[ ${#_NAMES[@]} -eq 0 ]] && return 0
  local printed=0
  for i in "${!_NAMES[@]}"; do
    local rc
    rc=$(cat "${_TMPDIR:-/nonexistent}/${i}.rc" 2>/dev/null || echo "")
    [[ -z "$rc" || "$rc" -eq 0 ]] && continue
    [[ $printed -eq 0 ]] && { printf '\n'; printed=1; }
    printf '::group::%s (FAILED — rc=%s)\n' "${_NAMES[$i]}" "$rc"
    cat "${_LOGS[$i]}" 2>/dev/null || true
    printf '::endgroup::\n'
  done
}

main() {
  trap _cleanup EXIT

  declare -g  _TMPDIR=
  declare -g  _HEARTBEAT_PID=
  declare -g  _FAIL_FAST=true
  declare -ga _NAMES=()
  declare -ga _CMDS=()
  declare -ga _PIDS=()
  declare -ga _LOGS=()
  declare -ga _FAILED_NAMES=()

  _parse_args "$@"

  if [[ ${#_NAMES[@]} -eq 0 ]]; then
    printf '::warning::parallel-run: no tasks given\n'
    return 0
  fi

  SECONDS=0
  _launch
  _start_heartbeat
  _wait

  if [[ ${#_FAILED_NAMES[@]} -gt 0 ]]; then
    printf '::error::Failed tasks: %s\n' "${_FAILED_NAMES[*]}"
    return 1
  fi
}

main "$@"

