# Feed System

## Overview

Add a persistent feed system parallel to the existing 1:1 messaging. Feeds enable broadcast/timeline content where an account owner publishes encrypted posts to selected friends. Unlike messages (ephemeral, 30-day TTL, ack-and-delete), feeds are permanent and server-persisted.

## Scope Updates

- `feedId` is client-generated during creation so feed metadata encryption and owner key derivation can include the final feed ID before the first API call.
- `currentEpoch` is persisted directly on `Feed`; the original conceptual-only epoch was not enough for the planned owned/following list APIs.
- Feed-item attachment ciphertext is stored inside the encrypted feed item payload so the server can persist permanent attachment bytes alongside the post.

**Key properties:**
- Each account can own multiple feeds
- Owner adds/removes members (friends) to each feed
- Feed items (text + attachments) are encrypted with a per-feed symmetric key
- Feed metadata (name, description) is encrypted so only the owner can read it
- The feed symmetric key is encrypted to each member's public key (X25519 box)
- Key rotation on membership change: new key epoch, old content stays readable with old key
- Clients fetch feed items across all followed feeds in time order
- Clients fetch all feed keys (encrypted to their identity) in one call

## Context

- **Existing crypto**: Ed25519 identity keys, X25519 DH keys (derived from identity), AES-256-GCM AEAD, HKDF-SHA-256
- **Existing patterns**: Prekey upload/fetch, message send/inbox/stream, cursor-based pagination, signature verification, Redis event bus for real-time
- **Server**: Prisma + PostgreSQL, Hono routes, Redis Streams for events
- **Client**: Noble crypto, SQLite storage, CLI commands + MCP tools
- **No existing feed/group concepts** — this is greenfield

## Development Approach
- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**

## Testing Strategy
- **Unit tests**: Required for every task — crypto functions, serialization, API routes
- **Integration tests**: Server route tests with real database (PGlite or test DB)
- **Client tests**: Encryption/decryption round-trips, state serialization

## Data Model

### Feed (server)

```
Feed
  id          String    @id @default(cuid())
  ownerId     String    (User identity key)
  metadata    Bytes     (encrypted blob — only owner can decrypt)
  createdAt   DateTime
  updatedAt   DateTime
```

### FeedMember (server)

```
FeedMember
  id          String    @id @default(cuid())
  feedId      String
  memberId    String    (member's identity key)
  epoch       Int       (key epoch — increments on rotation)
  encryptedKey Bytes    (feed symmetric key encrypted to member's X25519 public key)
  createdAt   DateTime

  @@unique([feedId, memberId, epoch])
```

### FeedItem (server)

```
FeedItem
  id          String    @id @default(cuid())
  feedId      String
  authorId    String    (always the feed owner)
  epoch       Int       (which key epoch this was encrypted with)
  blob        Bytes     (encrypted content — text + attachments)
  signature   Bytes     (Ed25519 signature by author)
  createdAt   DateTime

  @@index([feedId, createdAt])
```

### Feed Key Epoch (conceptual)

Each feed tracks its current epoch (integer). On membership change:
1. Increment epoch
2. Generate new symmetric key
3. Encrypt new key to all current members
4. New posts use new epoch; old posts stay readable with old epoch key

### Client-side Types

```typescript
interface FeedState {
  feedId: string;
  epoch: number;
  // Owner: keys derived on-the-fly from identity key, no storage needed
  // Member: keys received encrypted, must be stored
  keys: Map<number, Uint8Array>; // epoch → symmetric key (for members)
}

interface FeedMetadata {
  name: string;
  description?: string;
}

interface FeedItemContent {
  text: string;
  attachments?: Record<string, {
    hash: string;
    iv: string;
    key: string;
  }>;
}
```

### Encryption Scheme

- **Feed symmetric key**: Derived from owner's identity private key — `HKDF(ikm: identityPrivateKey, salt: feedId, info: "murmur-feed-key-" + epoch)`. Owner can always re-derive; no extra secret to store.
- **Key distribution**: `crypto_box_seal` equivalent — X25519 anonymous box to member's DH public key (derived from identity Ed25519 key)
- **Feed item encryption**: AES-256-GCM with random IV, using derived feed key at current epoch
- **Feed metadata encryption**: AES-256-GCM with random IV, using a separate owner-only key derived from identity key + feed ID via HKDF
- **Signatures**: Ed25519 sign (blob bytes + feedItemId bytes), same pattern as messages

## API Endpoints

### Feed Management

**POST `/v1/feeds/create`** — Create a new feed
- Auth: Bearer token
- Body: `{ metadata: string (base64 encrypted blob) }`
- Creates feed with epoch 0, client derives feed key from identity key + feedId
- Returns: `{ feedId, createdAt }`

**POST `/v1/feeds/:feedId/update`** — Update feed metadata
- Auth: Bearer token (must be owner)
- Body: `{ metadata: string (base64 encrypted blob) }`
- Returns: `{ feedId, updatedAt }`

**DELETE `/v1/feeds/:feedId`** — Delete a feed
- Auth: Bearer token (must be owner)
- Cascades: deletes all items, members, keys
- Returns: `{ success: true }`

**GET `/v1/feeds/owned`** — List feeds you own
- Auth: Bearer token
- Returns: `{ feeds: [{ feedId, metadata, epoch, createdAt, updatedAt }] }`

### Membership Management

**POST `/v1/feeds/:feedId/members/add`** — Add members
- Auth: Bearer token (must be owner)
- Body: `{ members: [{ memberId: string, encryptedKey: string (base64) }], epoch: number }`
- Returns: `{ added: number }`

**POST `/v1/feeds/:feedId/members/remove`** — Remove members
- Auth: Bearer token (must be owner)
- Body: `{ memberIds: string[] }`
- Returns: `{ removed: number }`
- Note: Client should follow up with key rotation (new epoch + re-encrypt for remaining members)

**POST `/v1/feeds/:feedId/keys/rotate`** — Rotate feed key (new epoch)
- Auth: Bearer token (must be owner)
- Body: `{ epoch: number, members: [{ memberId: string, encryptedKey: string (base64) }] }`
- Increments epoch, stores new encrypted keys for all current members
- Returns: `{ epoch: number }`

### Feed Content

**POST `/v1/feeds/:feedId/items/post`** — Post a feed item
- Auth: Bearer token (must be owner)
- Body: `{ itemId: string (cuid2), epoch: number, blob: string (base64), signature: string (base64) }`
- Signature covers: blob bytes + itemId bytes (same pattern as messages)
- Returns: `{ itemId, createdAt }`

**DELETE `/v1/feeds/:feedId/items/:itemId`** — Delete a feed item
- Auth: Bearer token (must be owner)
- Returns: `{ success: true }`

### Feed Reading (for members)

**GET `/v1/feeds/following`** — List feeds you're a member of
- Auth: Bearer token
- Returns: `{ feeds: [{ feedId, ownerId, epoch }] }`

**GET `/v1/feeds/keys`** — Get all feed keys for feeds you follow
- Auth: Bearer token
- Returns: `{ keys: [{ feedId, epoch, encryptedKey: string (base64) }] }`
- Returns all epochs so client can decrypt historical content

**GET `/v1/feeds/timeline`** — Fetch feed items across all followed feeds
- Auth: Bearer token
- Query: `limit` (default 50, max 100), `cursor` (base64 timestamp)
- Returns items from all feeds you're a member of, ordered by createdAt DESC
- Returns: `{ items: [{ feedId, itemId, authorId, epoch, blob, signature, createdAt }], nextCursor, hasMore }`

**GET `/v1/feeds/:feedId/items`** — Fetch items from a specific feed
- Auth: Bearer token (must be member or owner)
- Query: `limit`, `cursor`
- Returns: `{ items: [...], nextCursor, hasMore }`

### Real-time

- Extend existing Redis event bus: publish `feed:new_item` events
- SSE stream includes feed events for followed feeds

## Implementation Steps

### Task 1: Prisma schema — Feed, FeedMember, FeedItem models
- [ ] Add `Feed` model with id, ownerId, metadata, timestamps
- [ ] Add `FeedMember` model with feedId, memberId, epoch, encryptedKey, unique constraint
- [ ] Add `FeedItem` model with feedId, authorId, epoch, blob, signature, createdAt, indexes
- [ ] Add relations to existing User model
- [ ] Run `prisma migrate dev` to generate migration
- [ ] Verify migration applies cleanly

### Task 2: Feed crypto primitives (client)
- [ ] Create `src/encryption/feed/` directory with types.ts
- [ ] Define FeedState, FeedMetadata, FeedItemContent types
- [ ] Implement `deriveFeedKey(identityPrivateKey, feedId, epoch)` — HKDF-derived symmetric key
- [ ] Implement `encryptFeedKey(feedKey, recipientDHPublicKey)` — X25519 sealed box
- [ ] Implement `decryptFeedKey(encryptedKey, recipientDHPrivateKey)` — unseal
- [ ] Implement `encryptFeedItem(content, feedKey)` — AES-256-GCM
- [ ] Implement `decryptFeedItem(blob, feedKey)` — AES-256-GCM
- [ ] Implement `encryptFeedMetadata(metadata, identityKey, feedId)` — HKDF-derived key
- [ ] Implement `decryptFeedMetadata(blob, identityKey, feedId)` — HKDF-derived key
- [ ] Write tests for key derivation (deterministic, different per feed/epoch)
- [ ] Write tests for key distribution (encrypt to recipient, decrypt by recipient)
- [ ] Write tests for metadata encryption (owner can decrypt, others cannot)
- [ ] Run tests — must pass before next task

### Task 3: Server routes — Feed CRUD and membership
- [ ] Create `packages/murmur-server/sources/api/routes/v1/feeds.ts`
- [ ] Implement POST `/v1/feeds/create` — create feed with metadata
- [ ] Implement POST `/v1/feeds/:feedId/update` — update metadata (owner only)
- [ ] Implement DELETE `/v1/feeds/:feedId` — delete feed with cascade (owner only)
- [ ] Implement GET `/v1/feeds/owned` — list owned feeds
- [ ] Implement POST `/v1/feeds/:feedId/members/add` — add members with encrypted keys
- [ ] Implement POST `/v1/feeds/:feedId/members/remove` — remove members
- [ ] Implement POST `/v1/feeds/:feedId/keys/rotate` — rotate key epoch
- [ ] Register routes in router
- [ ] Write tests for feed CRUD (create, update, delete, list)
- [ ] Write tests for membership (add, remove, authorization)
- [ ] Write tests for key rotation (epoch increment, key distribution)
- [ ] Run tests — must pass before next task

### Task 4: Server routes — Feed content and timeline
- [ ] Implement POST `/v1/feeds/:feedId/items/post` — post item with signature verification
- [ ] Implement DELETE `/v1/feeds/:feedId/items/:itemId` — delete item (owner only)
- [ ] Implement GET `/v1/feeds/following` — list feeds user is member of
- [ ] Implement GET `/v1/feeds/keys` — get all encrypted keys for followed feeds
- [ ] Implement GET `/v1/feeds/timeline` — cross-feed timeline with cursor pagination
- [ ] Implement GET `/v1/feeds/:feedId/items` — single feed items with cursor pagination
- [ ] Add feed events to Redis event bus (`feed:new_item`)
- [ ] Write tests for posting items (success, authorization, signature verification)
- [ ] Write tests for timeline pagination (ordering, cursor, cross-feed)
- [ ] Write tests for key fetching (all epochs returned)
- [ ] Run tests — must pass before next task

### Task 5: Client API and feed engine
- [ ] Add feed API methods to client API module (create, update, delete, addMembers, removeMembers, rotateKeys, postItem, deleteItem, timeline, feedItems, keys, following)
- [ ] Implement feed engine: create feed (generate key, encrypt metadata, call API, encrypt key for self)
- [ ] Implement feed engine: add member (encrypt current feed key to member's DH key, call API)
- [ ] Implement feed engine: remove member + rotate (generate new key, re-encrypt for remaining members)
- [ ] Implement feed engine: post item (encrypt content with feed key, sign, call API)
- [ ] Implement feed engine: fetch timeline (get keys, decrypt items)
- [ ] Implement feed engine: sync keys (fetch all encrypted keys, decrypt and store locally)
- [ ] Write tests for feed engine create/post/decrypt round-trip
- [ ] Write tests for member add/remove with key rotation
- [ ] Run tests — must pass before next task

### Task 6: Client storage — SQLite persistence for feed state
- [ ] Add feed tables to SQLite schema (feeds, feed_keys, feed_items cache)
- [ ] Implement feed state serialization/deserialization
- [ ] Implement local feed key storage (all epochs per feed)
- [ ] Implement local feed item cache (decrypted items for offline access)
- [ ] Write tests for persistence round-trips
- [ ] Run tests — must pass before next task

### Task 7: CLI commands and MCP tools
- [ ] Add `murmur feed create --name "..."` command
- [ ] Add `murmur feed list` command (owned feeds)
- [ ] Add `murmur feed members add --feed <id> --member <id>` command
- [ ] Add `murmur feed members remove --feed <id> --member <id>` command
- [ ] Add `murmur feed post --feed <id> --message "..." [--attach file]` command
- [ ] Add `murmur feed timeline` command (cross-feed, paginated)
- [ ] Add `murmur feed items --feed <id>` command
- [ ] Add corresponding MCP tools for feed operations
- [ ] Write tests for CLI argument parsing
- [ ] Run tests — must pass before next task

### Task 8: Verify acceptance criteria
- [ ] Verify: account can create multiple feeds
- [ ] Verify: owner can add/remove friends to specific feeds
- [ ] Verify: feed metadata is encrypted and only owner can read it
- [ ] Verify: feed key is shared encrypted with member public keys
- [ ] Verify: server persists all feed content permanently
- [ ] Verify: timeline fetches across all followed feeds in time order
- [ ] Verify: key rotation works on membership change
- [ ] Run full test suite
- [ ] Run linter — all issues must be fixed

### Task 9: [Final] Update documentation
- [ ] Update CLAUDE.md with feed system details
- [ ] Update API docs if they exist
- [ ] Update protocol docs with feed encryption scheme

## Technical Details

### Key Distribution Flow

```
Owner creates feed:
1. Derive feedKey = HKDF(identityPrivateKey, feedId, "murmur-feed-key-0")
2. Encrypt metadata with HKDF(identityKey, feedId) (separate derivation path)
3. POST /v1/feeds/create
4. Encrypt feedKey to own DH public key → store as FeedMember

Owner adds member:
1. Derive feedKey for current epoch (re-derive from identity key)
2. Derive member's DH public key from their Ed25519 identity key
3. Encrypt feedKey to member's DH public key
4. POST /v1/feeds/:feedId/members/add

Owner removes member:
1. POST /v1/feeds/:feedId/members/remove
2. Derive new feedKey for epoch N+1 = HKDF(identityPrivateKey, feedId, "murmur-feed-key-{N+1}")
3. Encrypt new feedKey to all remaining members
4. POST /v1/feeds/:feedId/keys/rotate

Member reads feed:
1. GET /v1/feeds/keys → all encrypted keys
2. Decrypt each key with own DH private key
3. GET /v1/feeds/timeline → encrypted items
4. Decrypt each item with appropriate epoch key
```

### Sealed Box Construction

Since we use Noble crypto (no libsodium), implement sealed box as:
1. Generate ephemeral X25519 keypair
2. DH(ephemeral_private, recipient_public) → shared secret
3. HKDF(shared_secret, ephemeral_public) → symmetric key
4. AES-256-GCM encrypt(symmetric_key, feedKey)
5. Output: ephemeral_public || ciphertext

This is equivalent to NaCl crypto_box_seal.

### Metadata Encryption

Owner-only key derived as:
```
metadataKey = HKDF-SHA-256(
  ikm: identityPrivateKey,
  salt: SHA-256("murmur-feed-metadata"),
  info: feedId
)
```

This ensures only the identity key holder can decrypt metadata.

## Post-Completion

**Manual verification:**
- Test multi-device scenario: keys sync correctly across devices
- Test with multiple feeds and members: timeline ordering is correct
- Verify removed members cannot decrypt new posts

**Future considerations:**
- Feed item editing (new item replacing old)
- Read receipts / seen tracking
- Feed discovery (public feeds)
- Feed item reactions
