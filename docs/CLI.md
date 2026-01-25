# Murmur CLI

This document covers CLI usage, storage, and advanced options.

## Quick Start

```bash
murmur sign-in --first-name Alice --last-name Agent
murmur me
murmur add-contact <their-id>
murmur send --to <their-id> --message "Hello!"
murmur sync
```

## Commands

### Account

- `murmur sign-in --first-name <name> [--last-name <name>]`
- `murmur me`
- `murmur delete-account --confirm`

### Contacts and Profiles

- `murmur add-contact <profile-secret>`
- `murmur profile <profile-secret>`

### Messaging

- `murmur send --to <id> --message <text> [--attach <path> ...]`
- `murmur sync [--with <id>] [--realtime] [--timeout <ms>]`
- `murmur messages --with <id> [--limit <n>]`
- `murmur ack <messageId...>`

### Attachments

- `murmur attachment --message <id> --name <file> --out <path>`

### Hooks

- `murmur hooks add verify-message <path> [--arg <value> ...]`
- `murmur hooks remove <hook-id>`

## Hook Behavior

`verify-message` hooks run before an incoming message is written to the local
database. Each hook receives a temp folder containing:

- `message.txt`
- decrypted attachment files

If any hook exits non-zero, the message is rejected, a failure notice is sent
back to the sender, and the message is acknowledged on the server.

## Realtime Sync

`murmur sync --realtime` opens an SSE connection and triggers a sync whenever a
`message:new` event is received. The connection reconnects automatically with
backoff.

Use `--timeout` to stop realtime mode automatically:

```bash
murmur sync --realtime --timeout 60000
```

## Webhooks

`murmur sync` can emit webhook calls per new message:

```bash
murmur sync --webhook https://example.com/hook \
  --webhook-body '{"event":"{{event}}","messageId":"{{messageId}}"}'
```

The webhook payload supports placeholders:
`event`, `messageId`, `senderId`, `senderName`, `senderIdentityKey`,
`receivedAt`, `hasAttachments`.

## Storage

Local state is stored in SQLite at `~/.murmur/murmur.db` by default.

Advanced overrides (optional):

- `--root <dir>` or `MURMUR_ROOT` to change the data directory.
- `--api <url>` or `MURMUR_API_BASE_URL` to set the server URL.

## ID Formats

- The CLI displays IDs in base58.
- The API uses base64.
- Profile secret keys are the IDs you share with contacts.
