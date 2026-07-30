# Murmur CLI

The Node command-line client for the new Murmur architecture. It uses the
`@slopus/murmur` library for identities, contacts, direct messages, encrypted
files, durable relay queues, exactly-once application acceptance, and MLS group
state.

Node 22.5 or later is required because durable local state uses `node:sqlite`.

## Relay and storage

Start a relay with `murmur-relay`, then select it with `--relay` or
`MURMUR_RELAYS`. State defaults to `~/.murmur/murmur.sqlite`; use `--db` or
`MURMUR_HOME` to isolate identities.

```bash
murmur --relay http://127.0.0.1:8787 sign-in --first-name Alice
murmur me
```

`murmur me` prints a token containing both public identity keys. Two people add
one another by sending their encrypted profiles, then synchronize:

```bash
murmur contacts add <identity-token>
murmur sync
murmur contacts
```

## Private messages and files

```bash
murmur send --to <identity-id> --message "hello"
murmur send --to <identity-id> --message "attached" --attach ./note.txt
murmur sync
murmur messages --with <identity-id>
murmur attachment --message <message-id> --name note.txt --out ./note.txt
```

All command results are JSON except `help`. File bytes are encrypted before
upload; received message history and replay state commit atomically before the
relay delivery is acknowledged. One message may carry at most 64 attachments
and 64 MiB of aggregate plaintext attachment data.

## MLS groups

Profile exchange also distributes a signed one-use RFC KeyPackage. Create a
group, invite an authenticated contact, and exchange forward-secret group
messages:

```bash
murmur groups create --name "Protocol team"
murmur groups invite --group <group-id> --contact <identity-id>
murmur sync
murmur groups send --group <group-id> --message "hello"
murmur groups messages --group <group-id>
murmur groups remove --group <group-id> --contact <identity-id>
```

Welcome, Commit, epoch checkpoints, replay markers, and exact relay events use
ordered durable outboxes. A restart cannot publish a Commit without its
corresponding next-epoch private state.

## Shared documents

Documents are operation-based replicated text objects carried as ordinary MLS
application messages; relays see the same opaque group ciphertext as chat.

```bash
murmur documents create --group <group-id> --name "Draft"
murmur documents insert --document <document-id> --text "hello"
murmur documents
murmur documents delete --document <document-id> --target <actor>:<sequence>
```

Concurrent inserts converge by canonical operation ID. Every mutation actor is
bound to the authenticated MLS leaf before its CRDT state and post-open epoch
checkpoint are committed atomically.

## Development

```bash
pnpm --filter murmur-chat test
pnpm --filter murmur-chat typecheck
pnpm --filter murmur-chat build
```

The new implementation lives in `sources`. The historical `src` tree is not
included in the package build and remains only as temporary migration reference.
