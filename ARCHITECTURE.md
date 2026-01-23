# Murmur Server Architecture

## Overview

Murmur is a secure message relay server using NaCl (TweetNaCl) public key cryptography for authentication and message signing. It acts as a message broker, forwarding signed encrypted blobs between users without ever decrypting them.

## Key Concepts

### Identity-Based Authentication

- Users are identified by their Ed25519 public keys (NaCl signing keys)
- No passwords or traditional accounts
- Authentication uses cryptographic signatures
- JWT tokens are issued after signature verification

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

### 1. EventBus (Redis + PostgreSQL)

The EventBus enables reliable event distribution across multiple server instances:

**Architecture:**
- Redis pub/sub for fast real-time event delivery
- PostgreSQL for durable sequence number checkpoints
- Atomic operations to prevent race conditions

**Sequence Numbers:**
- Each user has a monotonic counter (seqno)
- Stored in Redis (fast, volatile)
- Checkpointed to DB every 10 seconds (durable)
- Gaps are acceptable (uniqueness guaranteed)

**Redis Recovery:**
When Redis restarts or connection is lost:
1. Process atomically increments DB checkpoint by 1000
2. Sets Redis to max(current, checkpoint) using Lua script
3. Resumes counting from new checkpoint

This creates sequence gaps but guarantees:
- No duplicate sequence numbers
- No race conditions between processes
- Survives Redis restarts

**Race Condition Prevention:**

Three critical race conditions are handled:

1. **DB Checkpoint Recovery**: Multiple processes incrementing checkpoint
   - Solution: Atomic `UPDATE...RETURNING` with row-level lock
   - Each process gets unique checkpoint (1000, 2000, 3000...)

2. **Redis Write-Back**: Later process overwrites with smaller value
   - Solution: Lua script `SET MAX(current, new)`
   - Ensures Redis always has highest value

3. **Periodic Checkpoints**: Old checkpoint overwrites new
   - Solution: SQL `GREATEST(current, new)`
   - Only updates if new value is higher

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

### User
```
id: string (Ed25519 public key, base64)
createdAt: DateTime
profilePublicKey: string (NaCl public key for profile)
profileKeySignature: JSON (signature of profilePublicKey by id)
encryptedProfile: JSON (encrypted profile data)
profileUpdatedAt: DateTime
```

### Message
```
id: string (CUID)
createdAt: DateTime
expiresAt: DateTime (createdAt + 30 days)
deliveredAt: DateTime | null
senderId: string (User.id)
recipientId: string (User.id)
blob: JSON (encrypted message)
signature: JSON (NaCl signature of blob)
```

### UserSequence
```
userId: string (User.id)
seqno: int (monotonic counter)
updatedAt: DateTime
```

## Security Considerations

### Signature Verification

All critical operations require signature verification:
- Registration: Request signed by identity key
- Login: Timestamp signed by identity key
- Profile update: Request signed by identity key
- Message send: Blob signed by sender's identity key
- Profile key: Signed by identity key

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
- EventBus coordinates via Redis
- Each instance has own DB connection pool
- SSE connections distributed across instances
- Sequence numbers remain unique via atomic DB operations

### Database

PostgreSQL chosen for:
- ACID guarantees for sequence numbers
- Atomic `UPDATE...RETURNING` for checkpoints
- Efficient indexing for message queries
- JSON support for flexible blob storage

### Redis

Used for:
- Pub/sub event distribution
- Volatile sequence number counters
- Fast reads (no DB hit for increments)

Configured with:
- AOF persistence (append-only file)
- Ensures sequence data survives restarts
- Acceptable to lose few seconds on crash

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
- `JWT_SECRET`: Secret for JWT signing
- `PORT`: HTTP port (default 3000)

## Future Enhancements

Potential improvements:
1. Rate limiting per user
2. Message size limits
3. WebSocket support alongside SSE
4. Message read receipts
5. Multi-recipient messages (groups)
6. Message forwarding/routing
7. Metrics and monitoring
8. Admin API for user management
