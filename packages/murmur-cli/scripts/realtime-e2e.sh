#!/usr/bin/env bash
set -euo pipefail

CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALICE_DIR="$(mktemp -d)"
BOB_DIR="$(mktemp -d)"
WORK_DIR="$(mktemp -d)"
LOG_FILE="${WORK_DIR}/bob-realtime.log"

cleanup() {
    set +e
    yarn --cwd "${CLI_DIR}" -s dev --root "${ALICE_DIR}" delete-account --confirm >/dev/null 2>&1 || true
    yarn --cwd "${CLI_DIR}" -s dev --root "${BOB_DIR}" delete-account --confirm >/dev/null 2>&1 || true
    rm -rf "${ALICE_DIR}" "${BOB_DIR}" "${WORK_DIR}"
}
trap cleanup EXIT

murmur() {
    local root="$1"
    shift
    yarn --cwd "${CLI_DIR}" -s dev --root "${root}" "$@"
}

extract_id() {
    local output="$1"
    echo "${output}" | awk -F': ' '/^ID: /{print $2; exit}'
}

echo "Creating accounts..."
murmur "${ALICE_DIR}" sign-in --first-name Alice --last-name Realtime >/dev/null
murmur "${BOB_DIR}" sign-in --first-name Bob --last-name Realtime >/dev/null

alice_id="$(extract_id "$(murmur "${ALICE_DIR}" me)")"
bob_id="$(extract_id "$(murmur "${BOB_DIR}" me)")"

if [[ -z "${alice_id}" || -z "${bob_id}" ]]; then
    echo "Failed to parse profile IDs."
    exit 1
fi

echo "Adding contacts..."
murmur "${ALICE_DIR}" contacts add "${bob_id}" >/dev/null
murmur "${BOB_DIR}" contacts add "${alice_id}" >/dev/null

echo "Starting realtime sync for Bob..."
murmur "${BOB_DIR}" sync --realtime --timeout 15000 >"${LOG_FILE}" 2>&1 &
SYNC_PID=$!

sleep 2

echo "Sending message from Alice..."
murmur "${ALICE_DIR}" send --to "${bob_id}" --message "Realtime hello" >/dev/null

wait "${SYNC_PID}" || true

if ! grep -q "Realtime hello" "${LOG_FILE}"; then
    echo "Realtime sync did not print the message."
    echo "Log output:"
    cat "${LOG_FILE}"
    exit 1
fi

echo "Realtime sync check passed."
