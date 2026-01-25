#!/usr/bin/env bash
set -euo pipefail

CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALICE_DIR="$(mktemp -d)"
BOB_DIR="$(mktemp -d)"
WORK_DIR="$(mktemp -d)"

ALICE_FILE="${WORK_DIR}/alice-note.txt"
BOB_FILE="${WORK_DIR}/bob-note.txt"
ALICE_OUT="${WORK_DIR}/alice-received.txt"
BOB_OUT="${WORK_DIR}/bob-received.txt"

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

extract_message_id() {
    local output="$1"
    echo "${output}" | awk -F': ' '/^Message ID: /{print $2; exit}'
}

echo "Creating accounts..."
murmur "${ALICE_DIR}" sign-in --first-name Alice --last-name E2E >/dev/null
murmur "${BOB_DIR}" sign-in --first-name Bob --last-name E2E >/dev/null

alice_me="$(murmur "${ALICE_DIR}" me)"
bob_me="$(murmur "${BOB_DIR}" me)"

alice_id="$(extract_id "${alice_me}")"
bob_id="$(extract_id "${bob_me}")"

if [[ -z "${alice_id}" || -z "${bob_id}" ]]; then
    echo "Failed to parse profile IDs."
    exit 1
fi

echo "Adding contacts..."
murmur "${ALICE_DIR}" add-contact "${bob_id}" >/dev/null
murmur "${BOB_DIR}" add-contact "${alice_id}" >/dev/null

printf 'Hello from Alice attachment.\n' > "${ALICE_FILE}"
printf 'Hello from Bob attachment.\n' > "${BOB_FILE}"

echo "Sending messages with attachments..."
murmur "${ALICE_DIR}" send --to "${bob_id}" --message "Hello Bob (with attachment)" --attach "${ALICE_FILE}" >/dev/null
murmur "${BOB_DIR}" send --to "${alice_id}" --message "Hello Alice (with attachment)" --attach "${BOB_FILE}" >/dev/null

echo "Syncing Bob..."
bob_sync="$(murmur "${BOB_DIR}" sync)"
echo "${bob_sync}" | grep -q "Hello Bob (with attachment)"
echo "${bob_sync}" | grep -q "Attachments: $(basename "${ALICE_FILE}")"

bob_msg_id="$(extract_message_id "${bob_sync}")"
if [[ -z "${bob_msg_id}" ]]; then
    echo "Failed to parse Bob's message ID."
    exit 1
fi

echo "Saving Alice attachment from Bob's inbox..."
murmur "${BOB_DIR}" attachment --message "${bob_msg_id}" --name "$(basename "${ALICE_FILE}")" --out "${BOB_OUT}" >/dev/null
cmp -s "${ALICE_FILE}" "${BOB_OUT}"

echo "Syncing Alice..."
alice_sync="$(murmur "${ALICE_DIR}" sync)"
echo "${alice_sync}" | grep -q "Hello Alice (with attachment)"
echo "${alice_sync}" | grep -q "Attachments: $(basename "${BOB_FILE}")"

alice_msg_id="$(extract_message_id "${alice_sync}")"
if [[ -z "${alice_msg_id}" ]]; then
    echo "Failed to parse Alice's message ID."
    exit 1
fi

echo "Saving Bob attachment from Alice's inbox..."
murmur "${ALICE_DIR}" attachment --message "${alice_msg_id}" --name "$(basename "${BOB_FILE}")" --out "${ALICE_OUT}" >/dev/null
cmp -s "${BOB_FILE}" "${ALICE_OUT}"

echo "E2E check passed."
