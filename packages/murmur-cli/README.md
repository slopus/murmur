# Murmur CLI

The Node command-line client for the new Murmur architecture. It uses
`@murmur/core` for identities, contacts, direct messages, encrypted files,
durable relay queues, and exactly-once application acceptance. MLS group state
is layered through `@murmur/mls`.

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

## Development

```bash
pnpm --filter murmur-chat test
pnpm --filter murmur-chat typecheck
pnpm --filter murmur-chat build
```

The new implementation lives in `sources`. The historical `src` tree is not
included in the package build and remains only as temporary migration reference.
