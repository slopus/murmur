# Server Logic

This document explains how Murmur Server handles requests and moves data through the system.

## Startup Sequence

- `sources/main.ts` initializes JWT, database, EventBus, cleanup worker, metrics server, and API.
- Each component registers shutdown handlers to close connections cleanly.

## Request Authentication

- Public routes live under `sources/api/routes/v1/auth.ts`.
- All other `/v1` routes run the authentication hook in `sources/api/auth.ts`.
- The hook validates the Bearer access token and attaches `userId` to the request.

## Registration and Login

- **Register** (`POST /v1/auth/register`)
  - Validates key formats, sizes, timestamp window, and request signature.
  - Normalizes public keys to internal base64 before database operations.
  - Verifies that the profile public key is signed by the identity key.
  - Creates a user or returns idempotently when the same profile is re-submitted.
  - Issues access and refresh tokens.
- **Login** (`POST /v1/auth/login`)
  - Validates the identity public key and timestamp window.
  - Verifies the signature over `identityPublicKey:timestamp`.
  - Issues access and refresh tokens.
- **Refresh** (`POST /v1/auth/refresh`)
  - Verifies the refresh token and issues a new access token.

## Message Flow

- **Send** (`POST /v1/messages/send`)
  - Validates size limits and ensures `messageId` is a cuid2.
  - Ensures the recipient exists.
  - Verifies the signature over `blob + messageId`.
  - Stores the message with a 30-day expiration.
  - Publishes a Redis event and sends an SSE notification.
- **Inbox** (`GET /v1/messages/inbox`)
  - Returns unexpired messages for the recipient with cursor pagination.
- **Message by ID** (`GET /v1/messages/:messageId`)
  - Ensures the requester is the recipient and marks the message delivered.
- **Acknowledge** (`POST /v1/messages/ack`)
  - Deletes messages owned by the caller and returns multi-status results.
- **Stream** (`GET /v1/messages/stream`)
  - Opens an SSE connection, sends undelivered message IDs, and maintains heartbeats.

## Profile Flow

- **Read** (`GET /v1/profile/me` authenticated, `GET /v1/profile/:profilePublicKey` public)
  - Returns encrypted profile data plus the profile key signature.
- **Update** (`POST /v1/profile/update`)
  - Validates size limits and timestamp window.
  - Verifies the request signature and the profile key signature.
  - Stores the new encrypted profile and publishes a profile update event.
- **Delete** (`POST /v1/account/delete`)
  - Verifies the signed timestamp and deletes the account.

## PreKey Flow

- **Upload** (`POST /v1/prekeys/upload`)
  - Validates each prekey and the request signature.
  - Stores signed and one-time prekeys for later allocation.
- **Allocate** (`GET /v1/prekeys/:identityPublicKey`)
  - Returns the newest signed prekey and allocates it to the requester.
  - Allocates a one-time prekey if available.
- **Count** (`GET /v1/prekeys/onetime/count`)
  - Returns the remaining unallocated one-time prekeys for the caller.

## Event Bus

- Redis Streams provide durable delivery across nodes (`sources/eventbus/eventBus.ts`).
- Events are wrapped in envelopes, validated with Zod, and dispatched to handlers.
- Stream entries are acknowledged after dispatch.

## Storage and Retention

- PostgreSQL stores users, messages, and prekeys (`prisma/schema.prisma`).
- Messages have a fixed 30-day expiration timestamp.
- The cleanup worker deletes expired messages on an hourly loop.

## Metrics and Rate Limiting

- A separate metrics server exposes `/metrics` and health probes.
- Rate limits are configured per route group (`sources/api/rateLimit.ts`).
- Size limits for blobs and signatures live in `sources/api/validation.ts`.
