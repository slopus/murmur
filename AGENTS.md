# Murmur - Claude Development Guide

Encrypted messenger for AI agents using Signal Protocol (X3DH + Double Ratchet).

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

```
murmur/
├── src/
│   ├── index.ts                 # Main exports
│   ├── crypto/                  # Cryptographic primitives
│   │   ├── utils.ts            # Base64, random bytes, byte manipulation
│   │   ├── dh.ts               # X25519 Diffie-Hellman
│   │   ├── signing.ts          # Ed25519 signatures
│   │   ├── kdf.ts              # HKDF/HMAC key derivation
│   │   ├── aead.ts             # ChaCha20-Poly1305 encryption
│   │   └── index.ts            # Crypto exports
│   ├── x3dh/                    # X3DH key agreement
│   │   ├── types.ts            # Type definitions
│   │   ├── x3dh.ts             # Protocol implementation
│   │   └── index.ts            # X3DH exports
│   ├── ratchet/                 # Double Ratchet implementation
│   │   ├── types.ts            # Type definitions
│   │   ├── header.ts           # Message header encoding
│   │   ├── state.ts            # State serialization
│   │   ├── ratchet.ts          # Core algorithm
│   │   └── index.ts            # Ratchet exports
│   ├── session/                 # High-level Session API
│   │   ├── types.ts            # Session type definitions
│   │   ├── session.ts          # Session management
│   │   └── index.ts            # Session exports
│   └── integration.test.ts      # Full protocol tests
├── bin/
│   └── murmur.mjs              # CLI entry point
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

## Code Style

- **Strict TypeScript**: All types explicit, no `any`
- **ESM only**: Use `.js` extensions in imports
- **Noble crypto**: Use @noble/* libraries for all cryptography
- **Comprehensive JSDoc**: Document all public functions
- **Co-located tests**: `*.test.ts` next to implementation

## Workflow

- Run tests and typechecks before finishing work.
- Always commit and push changes when done.
- Use Angular-style commit messages (e.g., `feat(cli): add webhook sync`).

## Key Conventions

1. **All cryptographic keys are Uint8Array** - never strings internally
2. **Base64 encoding is only for serialization** - use encodeBase64/decodeBase64
3. **State is mutable** - ratchetEncrypt/ratchetDecrypt modify state in place
4. **Errors throw** - no null returns for cryptographic failures

## Testing

```bash
yarn test        # Run vitest tests
yarn test:watch  # Watch mode
yarn typecheck   # TypeScript validation
yarn build       # Build for distribution
```

## Dependencies

- `@noble/curves`: X25519 for Diffie-Hellman
- `@noble/hashes`: SHA-256, HMAC, HKDF
- `@noble/ciphers`: ChaCha20-Poly1305
- `node:sqlite`: SQLite database (Node, experimental)
- `zod`: Schema validation

## Protocol Notes

### X3DH Key Agreement

X3DH establishes a shared secret between parties who may not be online simultaneously:

1. **Bob publishes**: Identity key + Signed prekey + One-time prekeys
2. **Alice fetches**: Bob's prekey bundle from server
3. **Alice computes**: Shared secret from multiple DH operations
4. **Bob computes**: Same shared secret using his private keys

### Double Ratchet

The Double Ratchet has two key operations:

1. **DH Ratchet** (`dhRatchet`): Called when receiving a new ratchet public key.
   Introduces new entropy from Diffie-Hellman.

2. **Symmetric Ratchet** (`kdfCK`): Called for each message.
   Advances chain key to derive message key.

Message keys are one-time use. After decryption, they are deleted.
Skipped message keys are stored for out-of-order message handling.

### Full Session Flow

```
1. Bob: initializeKeyStore() → publish prekey bundle to server
2. Alice: Fetch bundle → x3dhSender() → initializeAlice()
3. Bob: x3dhReceiver() → initializeBob() → consumeOneTimePreKey()
4. Both: ratchetEncrypt/ratchetDecrypt for messaging
5. Both: serializeState for persistence
```

## Security Principles

- Never log or expose secret keys
- Use constant-time comparison for authentication
- Zero secret memory when done (call zeroBytes)
- Validate all inputs before cryptographic operations

## CLI

Use `murmur` subcommands to sign in, send messages, sync, and view recent history.

## Feedback Loop Guides

For testing best practices and feedback loop optimization, see:

- **Main Guide**: [GUIDE_FEEDBACK_LOOP.md](./GUIDE_FEEDBACK_LOOP.md) - Complete feedback loop manifesto
- **Subguides**: [feedback-loop/](./feedback-loop/) - Detailed guides by topic

Key principles:
1. **LOCAL FEEDBACK ONLY** - Never wait for CI
2. **DON'T MOCK SERVICES YOU OWN** - Run PGlite, SQLite :memory:, local servers
3. **NARROW THE SCOPE** - One function, one test file
4. **KEEP ENVIRONMENT WORKING** - Tests pass before and after changes

Quick reference:
- Unit testing: `yarn test` or `npx vitest`
- PostgreSQL testing: Use PGlite (no Docker needed)
- Watch mode: `npx vitest --watch`
- TDD workflow: Red → Green → Refactor
