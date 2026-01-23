# Murmur Server Architecture

## Overview

Murmur is a secure message relay server using NaCl (TweetNaCl) public key cryptography for authentication and message signing. It acts as a message broker, forwarding signed encrypted blobs between users without ever decrypting them.

## Key Concepts

### Identity-Based Authentication

- Users are identified by their Ed25519 public keys (NaCl signing keys)
- No passwords or traditional accounts
- Authentication uses cryptographic signatures
- JWT tokens are issued after signature verification using privacy-kit
- Tokens include both access tokens (24h expiration) and refresh tokens
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

The EventBus provides reliable event distribution using Redis Streams:

**Architecture:**
- Redis Streams for reliable message delivery (not pub/sub)
- Consumer groups for distributed message processing
- Messages persist until explicitly acknowledged
- Channel-based routing for future sharding capabilities

**Message Identification:**
- Messages identified by cuid2 IDs provided by sender
- No sequence numbers needed (distributed ID generation)
- Repeat protection via unique message IDs
- Format validation ensures only valid cuid2 IDs accepted

**Reliable Delivery:**
- Messages remain in stream until acknowledged
- Consumer groups track which messages each server has seen
- Multiple servers can process messages concurrently
- Messages can be acknowledged and deleted by clients

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
id: string (cuid2 provided by sender)
createdAt: DateTime
expiresAt: DateTime (createdAt + 30 days)
deliveredAt: DateTime | null
senderId: string (User.id)
recipientId: string (User.id)
blob: JSON (encrypted message)
signature: string (NaCl signature of blob + messageId)
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
- EventBus coordinates via Redis Streams consumer groups
- Each instance has own DB connection pool
- SSE connections distributed across instances
- Message IDs remain unique via cuid2 distributed generation
- Channel-based routing enables future sharding

### Database

PostgreSQL chosen for:
- ACID guarantees for sequence numbers
- Atomic `UPDATE...RETURNING` for checkpoints
- Efficient indexing for message queries
- JSON support for flexible blob storage

### Redis

Used for:
- Redis Streams for reliable event distribution
- Consumer groups for message processing
- Message persistence until acknowledged

Configured with:
- AOF persistence (append-only file)
- Ensures messages survive restarts
- Messages persist until explicitly deleted

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
- `JWT_PUBLIC_KEY`: Public key for JWT verification
- `PORT`: HTTP port (default 3000)

Generate JWT keys with: `yarn tsx scripts/generateKeys.ts`

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
