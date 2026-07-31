# Murmur - Claude Development Guide

End-to-end encrypted messaging for people and AI agents, over deliberately dumb
relays. Identities and direct messages use Ed25519 signatures and X25519 sealed
boxes; groups and shared objects use MLS (an RFC 9420 subset).

## Master plans

Read [`master-plans/00-master-plan.md`](master-plans/00-master-plan.md) first,
before any other work. It explains how master plans are used and maintained.
Then find every plan in [`master-plans/`](master-plans/) relevant to your task
and read each one in full before starting.

Master plans are dictated by the user and describe where the product is going,
in what order, and what counts as done. They outrank conclusions drawn from the
existing code. Do not create, edit, rename, or delete a file in `master-plans/`
unless the user explicitly asks for that change in the current task. When the
code contradicts a master plan, report the contradiction instead of revising the
plan.

All persistent plans must live in `master-plans/` and follow the master-plan
rules above. Do not create design documents, implementation plans, slash-command
plan artifacts, or planning directories anywhere else in the repository,
including `docs/plans/`.

## Project Structure

A pnpm workspace. Packages live in `packages/*`:

```
murmur/
├── master-plans/            # Product intent, read these first
├── docs/                    # Architecture and protocol reference
├── packages/
│   ├── murmur-core/         # @slopus/murmur, the single published library
│   ├── murmur-mls/          # MLS implementation, bundled into the library
│   ├── murmur-relay/        # Runtime-neutral dumb relay service + HTTP handler
│   ├── murmur-relay-node/   # SQLite store and Node HTTP host for the relay
│   └── murmur-cli/          # murmur-chat, the Node CLI
├── package.json             # Workspace scripts and shared dev tooling
├── pnpm-workspace.yaml
├── tsconfig.base.json       # Shared strict TypeScript options
├── .oxfmtrc.json            # Formatter config
└── .oxlintrc.json           # Linter config
```

`@slopus/murmur` is the only package published to npm as a library, plus
`murmur-chat` for the CLI. `@murmur/*` packages are internal to the workspace.

How code is laid out inside a package is dictated by
[`master-plans/02-code-organization.md`](master-plans/02-code-organization.md):
source in `sources`, `main.ts` for executables and `index.ts` for exported
packages, domain modules with an `impl` directory beneath them, `utils` for
self-contained helpers, tests in `tests` and `impl/tests`, and a `README.md` in
every directory. Read that plan before adding files. The existing packages
predate it and are not to be reorganized unless the user asks.

## Code Style

- **Strict TypeScript**: All types explicit, no `any`. New packages extend
  `tsconfig.base.json`.
- **ESM only**: Use `.js` extensions in imports
- **Noble crypto**: Use @noble/\* libraries for all cryptography
- **Comprehensive JSDoc**: Document all public functions
- **Tests in `tests` directories**: not beside the file they cover

## Tooling

- **pnpm** is the package manager. Never use yarn or npm here.
- **oxfmt** formats everything: four spaces, no tabs.
- **oxlint** lints everything.

## Workflow

- Run tests and typechecks before finishing work.
- Run `pnpm format` before every commit and include all of its output in the
  commit, including changes to files in `master-plans`.
- Always commit and push changes when done.
- Use Angular-style commit messages (e.g., `feat(cli): add webhook sync`).

## Key Conventions

1. **All cryptographic keys are Uint8Array** - never strings internally
2. **Base64url is only for serialization** - use encodeBase64Url/decodeBase64Url
   at wire and storage boundaries only
3. **Errors throw** - no null returns for cryptographic failures
4. **The application owns durability** - nothing is auto-acknowledged. Commit
   application state first, then acknowledge the delivery
5. **The relay is untrusted and dumb** - never add message semantics to it

## Testing

```bash
pnpm test          # Run vitest tests across the workspace
pnpm typecheck     # TypeScript validation
pnpm build         # Build for distribution
pnpm lint          # oxlint
pnpm format        # oxfmt --write .
pnpm format:check  # oxfmt --check .
```

## Dependencies

The published library depends only on Noble:

- `@noble/curves`: Ed25519 signatures and X25519 Diffie-Hellman
- `@noble/hashes`: SHA-256, HMAC, HKDF
- `@noble/ciphers`: ChaCha20-Poly1305 and AES-GCM

`@slopus/murmur` must stay browser-safe: no `node:*` imports, no side effects.
`node:sqlite` (Node, experimental) is used only by the CLI and the Node relay
host, which is why those require Node 22.5 or later.

## Protocol Notes

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full description. The parts
that most often trip up a change:

### Identity

An identity is two independent key pairs: Ed25519 for signing and X25519 for
encryption. `identityId` is the base64url public signing key; the inbox topic
is derived by hashing it, so the relay routes without learning who you are.
There is no account and no server-side registry.

### Contacts

Adding a contact is one signed profile, sealed to the recipient's X25519 key and
published to their inbox topic. Profiles are bound to a specific recipient, so
they cannot be replayed at a third party. The exchange is two-directional:
receiving a profile authenticates the sender to you, not you to them.

### Direct messages

Signed, then sealed with an ephemeral X25519 key pair.
`acceptPrivateMessageFromContact` commits the application record and the replay
marker in one store transaction and reports `"opened"` or `"duplicate"`. Never
acknowledge a relay delivery before that transaction commits.

### MLS groups

Groups are forward-secret epochs over a TreeKEM ratchet tree. Every membership
change is a Commit that advances the epoch. All epochs of a group share one
opaque relay topic.

Outbound group work always follows **prepare → persist → publish**. A restart
must never be able to publish a Commit whose next-epoch private state was not
durably written first; that is what locks a member out of their own group.

### Shared documents

Operation-based replicated text carried as ordinary MLS application messages.
Operations are idempotent and commutative; deletes are tombstones that may
arrive before their target. Every operation's actor is bound to the
authenticated MLS leaf. No relay code knows a document exists.

## Security Principles

- Never log or expose secret keys
- Use constant-time comparison for authentication
- Zero secret memory when done (call zeroBytes)
- Validate all inputs before cryptographic operations

## CLI

`murmur` signs in, exchanges contacts, sends messages and attachments, syncs,
manages MLS groups, and edits shared documents. Every result is JSON except
`help`, so an agent can drive it directly. Run `murmur help` for the current
command list, and start a relay with `@murmur/relay-node` for local testing.

## Feedback Loop

1. **LOCAL FEEDBACK ONLY** - Never wait for CI
2. **DON'T MOCK SERVICES YOU OWN** - Run PGlite, SQLite :memory:, local servers
3. **NARROW THE SCOPE** - One function, one test file
4. **KEEP ENVIRONMENT WORKING** - Tests pass before and after changes

Quick reference:

- Unit testing: `pnpm test`, or `pnpm vitest` inside a package
- PostgreSQL testing: Use PGlite (no Docker needed)
- Watch mode: `pnpm vitest --watch`
- TDD workflow: Red → Green → Refactor
