# Murmur Development Guide

Stateful MLS sessions over authenticated encrypted identity queues. Accounts
are found through the relay's identity directory by exact public identity key;
the relay is a delivery buffer plus that directory — honest but not trusted:
it is relied on to do its job correctly, but it can never decrypt anything.

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
│   ├── murmur/              # @slopus/murmur, the single published library
│   └── murmur-relay/        # @slopus/murmur-relay, private relay infrastructure
├── package.json             # Workspace scripts and shared dev tooling
├── pnpm-workspace.yaml
├── tsconfig.base.json       # Shared strict TypeScript options
├── .oxfmtrc.json            # Formatter config
└── .oxlintrc.json           # Linter config
```

`@slopus/murmur` is the only package published to npm.
`@slopus/murmur-relay` is private deployment infrastructure.

How code is laid out inside a package is dictated by
[`master-plans/02-code-organization.md`](master-plans/02-code-organization.md):
source in `sources`, `main.ts` for executables and `index.ts` for exported
packages, domain modules with an `impl` directory beneath them, `utils` for
self-contained helpers, tests in `tests` and `impl/tests`, and a `README.md` in
every directory. Read that plan before adding files.

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
- Use Angular-style commit messages (e.g., `feat(core): add durable group sync`).

## Key Conventions

1. **All cryptographic keys are Uint8Array** - never strings internally
2. **Base64url is only for serialization** - use encodeBase64Url/decodeBase64Url
   at wire and storage boundaries only
3. **Errors throw** - no null returns for cryptographic failures
4. **The application owns effects** - Murmur durably buffers updates before
   acknowledgement, calls the identity-wide `onUpdates` hook, and drains a
   whole batch only after the hook resolves
5. **The relay is honest but not trusted** - assume the server performs the
   protocol honestly, so it may hold authoritative MLS-adjacent state and
   enforce delivery and role rules (reject a publication that omits a current
   recipient device, enforce basic roles) as an addition to local member
   verification — never as a replacement, because it can never decrypt
   anything. The server can stop servicing something; that denial of service
   is accepted as unavoidable, since the server could shut down anyway
6. **One inbox per device, addressed by identity** - queue addresses are
   canonical Ed25519 keys, not anonymous topics or arbitrary routing labels
7. **No backward compatibility** - old APIs, wire formats, and schemas are
   deleted, not migrated or decoded; both deployed relays start clean

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
`node:sqlite` is used only by the relay package, which requires Node 22.5 or
later.

## Protocol Notes

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full description. The parts
that most often trip up a change:

### Identity, account secret, and directory

An identity exposes one Ed25519 public key; signing and X25519 key agreement
derive from one 32-byte root. A 1Password-like account secret — a strong
generated string plus the user password — wraps that root into an encrypted
blob the application persists; restoring the secret on a device is the entire
multidevice story, and losing it is final. Devices self-register in a
relay-held roster by proving key possession. The relay's identity directory
stores per-device pools of one-use prekeys plus one multi-use last-resort
prekey, resolvable only by the exact (unguessable) identity key and claimed
with a ticket from the authentication server. Everything the relay stores is
account-linked and removed by account or session deletion.

### Delivery queues

The relay stores unacknowledged and unexpired encrypted deliveries, directory
prekeys, and device rosters — nothing else. One atomic multicast receives one
UUIDv7 event ID and one reference in every exact recipient inbox, and a
publication that omits a current device of a targeted account is rejected with
the current roster so the sender re-encrypts. Streams carry each exact queued
delivery in inbox UUIDv7 order; durable signed acknowledgement remains
separate. Every inbox exposes a sequence number and loss generation so missed
deliveries are provable, never silent.

### MLS sessions

Two-person and many-person conversations use the same forward-secret TreeKEM
session. Every membership change is a Commit; any member may publish one, role
state validates it at every member, and relay delivery order resolves
concurrent Commits identically everywhere. The sender adopts its own Commit
only from the authenticated queue echo, never from publish success. Sessions
carry roles — owner, admins, membership policies, and a send policy — enforced
locally at send time and by every receiving member; the owner can delete the
session. Application sends persist the cloned post-ratchet epoch and exact
outbox before publication, and pending Welcome sessions continue MLS
processing while application events remain bounded and hidden until
activation.

## Security Principles

- Never log or expose secret keys
- Use constant-time comparison for authentication
- Zero secret memory when done (call zeroBytes)
- Validate all inputs before cryptographic operations

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
