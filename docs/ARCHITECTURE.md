# Murmur Server Architecture

## Overview

Murmur is a secure message relay server using Ed25519 public key cryptography for authentication and message signing. It acts as a message broker, forwarding signed encrypted blobs between users without ever decrypting them.

## Key Concepts

### Identity-Based Authentication

- Users are identified by their Ed25519 public keys (NaCl signing keys)
- No passwords or traditional accounts
- Authentication uses cryptographic signatures
- JWT tokens are issued after signature verification using privacy-kit
- Tokens include access tokens (configurable TTL, default 24h) and refresh tokens
- Automatic token refresh without re-authentication

### Signed Blobs

All messages and profile updates are:
1. Created as JSON blobs (encrypted by client)
2. Signed with the sender's private key
3. Verified by the server before storage
4. Forwarded as-is to recipients

The server never decrypts message contents, only verifies signatures.

### Profile System

Each user has two key pairs:
1. **Identity Key**: Ed25519 signing key (permanent identifier)
2. **Profile Key**: Separate key for profile encryption

The profile key is:
- Signed by the identity key (proves ownership)
- Used to encrypt the user's profile
- Can be rotated at any time

This separation allows profile key rotation without changing identity.

## Components

### 1. EventBus (Redis Streams)

The EventBus provides broadcast event distribution using Redis Streams:

**Architecture:**
- Redis Streams for durable event delivery (not pub/sub)
- Broadcast reads: each node reads the stream independently
- No consumer groups or acknowledgments required
- Channel-based routing for future sharding capabilities

**Message Identification:**
- Messages identified by cuid2 IDs provided by sender
- No sequence numbers needed (distributed ID generation)
- Repeat protection via unique message IDs
- Format validation ensures only valid cuid2 IDs accepted

**Delivery Model:**
- Each node receives all events and filters by channel
- Messages are stored in PostgreSQL; events are realtime hints
- Inbox messages are deleted via `/v1/messages/ack` (database)

**Channel-Based Routing:**
- Events published to channels (e.g., "user:userId", "global")
- Allows future sharding: route specific channels to specific servers
- Currently all channels processed globally
- Easy migration path to horizontal scaling

### 2. API Layer (Fastify)

**Authentication Flow:**
1. Client signs request with identity private key
2. Server verifies signature against identity public key
3. JWT issued for subsequent requests
4. JWT validated on authenticated routes

**Message Flow:**
1. Sender signs message blob
2. Server verifies signature
3. Message stored with 30-day expiration
4. Event published to recipient's EventBus channel
5. SSE notification sent if recipient connected
6. Recipient fetches from inbox

### 3. SSE (Server-Sent Events)

Real-time message delivery using SSE:
- Clients open `/v1/messages/stream` endpoint
- Connection managed per user
- Events pushed when messages arrive
- Automatic reconnection on disconnect
- Heartbeat every 30 seconds

**Why SSE over WebSocket:**
- Simpler protocol (one-way)
- Automatic reconnection in browsers
- Works over HTTP/2
- Lower overhead for notifications

### 4. Cleanup Worker

Background job that:
- Runs hourly
- Deletes messages with `expiresAt < now`
- Ensures 30-day auto-delete guarantee

## Data Models

Public keys are stored internally as standard base64 with padding, and API inputs/outputs use the same base64 encoding.

### User
```
id: string (Ed25519 public key, base64)
createdAt: DateTime
profilePublicKey: string (NaCl public key for profile)
profileKeySignature: Bytes (signature of profilePublicKey by id)
encryptedProfile: Bytes (encrypted profile data)
profileUpdatedAt: DateTime
```

### Message
```
id: string (cuid2 provided by sender)
createdAt: DateTime
expiresAt: DateTime (createdAt + 30 days)
deliveredAt: DateTime | null
senderId: string (User.id)
recipientId: string (User.id)
blob: Bytes (encrypted message)
signature: Bytes (NaCl signature of blob bytes + messageId bytes)
```

## Security Considerations

### Signature Verification

All critical operations require signature verification:
- Registration: Request signed by identity key
- Login: Timestamp signed by identity key
- Profile update: Request signed by identity key
- Message send: Blob + messageId signed by sender's identity key
- Profile key: Signed by identity key

### Message ID Security

Message IDs must be cuid2 format:
- Provided by sender (not auto-generated)
- Validated with isCuid() check
- Included in signature to prevent tampering
- Repeat protection via unique constraint
- Distributed ID generation prevents conflicts

### Timestamp Validation

To prevent replay attacks:
- Requests include timestamp
- Server checks timestamp is within 5 minutes
- Prevents old signatures from being reused

### Message Auto-Delete

Messages auto-delete after 30 days:
- Enforced at DB level with `expiresAt` field
- Cleanup worker ensures timely deletion
- Prevents unlimited data accumulation

### No Content Inspection

Server never decrypts:
- Message blobs (end-to-end encrypted by clients)
- Profile data (encrypted with profile key)

Server only:
- Verifies signatures
- Stores and forwards blobs
- Manages message lifecycle

## Scalability

### Horizontal Scaling

Multiple server instances can run simultaneously:
- EventBus coordinates via Redis Streams broadcast reads
- Each instance has own DB connection pool
- SSE connections distributed across instances
- Message IDs remain unique via cuid2 distributed generation
- Channel-based routing enables future sharding

### Database

PostgreSQL chosen for:
- ACID guarantees for message and profile writes
- Efficient indexing for message queries
- Reliable retention for encrypted blobs

### Redis

Used for:
-- Redis Streams for event distribution
-- Cross-node realtime notification delivery

Configured with:
- AOF persistence (append-only file)
- Ensures messages survive restarts
- Stream entries are trimmed by `EVENT_STREAM_MAXLEN`

## Deployment

### Docker Compose

Three services:
1. **PostgreSQL**: Persistent data storage
2. **Redis**: Event bus and caching
3. **Murmur**: Application server

Each service:
- Has health checks
- Persists data to volumes
- Restarts automatically

### Environment Variables

Required:
- `DATABASE_URL`: PostgreSQL connection
- `REDIS_URL`: Redis connection
- `JWT_SEED`: Seed for privacy-kit JWT token generation
- `PORT`: HTTP port (default 3000)
Optional:
- `ACCESS_TOKEN_TTL_MS`: Access token TTL in milliseconds
- `EVENT_STREAM_MAXLEN`: Redis stream trim length
- `METRICS_PORT`: Metrics server port
- `LOG_LEVEL`: Logging level

Generate a JWT seed with: `yarn tsx scripts/generateKeys.ts` (only `JWT_SEED` is used by the server)

## Future Enhancements

Potential improvements:
1. WebSocket support alongside SSE
2. Message read receipts
3. Multi-recipient messages (groups)
4. Message forwarding/routing
5. Admin API for user management
