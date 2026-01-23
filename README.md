# Murmur Server

Encrypted message transfer server with NaCl-based authentication. Messages are signed and forwarded as blobs with automatic 30-day expiration.

## Features

- **NaCl-based Authentication**: Identity based on public key cryptography (Ed25519)
- **JWT Tokens**: Generate JWTs from identity public keys for API access
- **Encrypted Profiles**: Each user has an encrypted profile with a separate encryption key (signed by identity key)
- **Message Inbox**: Receive signed message blobs with 30-day auto-delete
- **Real-time Updates**: SSE (Server-Sent Events) streaming for new messages
- **Multi-node Support**: Redis-based EventBus with persistent recovery
- **Signature Verification**: All messages and profile updates are cryptographically verified

## Architecture

### Components

- **Fastify API**: REST API with Zod validation
- **Prisma ORM**: PostgreSQL database with type-safe queries
- **EventBus**: Redis pub/sub with sequence numbers and DB checkpointing
- **SSE Streaming**: Real-time message delivery
- **Cleanup Worker**: Background job to delete expired messages

### EventBus Design

The EventBus provides reliable event distribution across multiple server nodes:

- **Redis Pub/Sub**: Fast event delivery between nodes
- **Sequence Numbers**: Monotonic counters per user for event ordering
- **DB Checkpointing**: Periodic writes to PostgreSQL for durability
- **Redis Recovery**: Automatic recovery after Redis restart without losing sequence order

## Getting Started

### Prerequisites

- Node.js 20+
- PostgreSQL
- Redis
- Yarn

### Installation

```bash
# Install dependencies
yarn install

# Setup environment variables
cp .env.example .env
# Edit .env with your configuration

# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Run migrations
yarn migrate

# Start the server
yarn start
```

### Docker Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f murmur

# Stop all services
docker-compose down
```

## API Endpoints

### Authentication

**Register**
```
POST /v1/auth/register
{
  "identityPublicKey": "base64-encoded-nacl-public-key",
  "profilePublicKey": "base64-encoded-profile-key",
  "profileKeySignature": "signature-of-profile-key-by-identity-key",
  "encryptedProfile": { ... },
  "timestamp": 1234567890,
  "signature": "signature-of-entire-request"
}
```

**Login**
```
POST /v1/auth/login
{
  "identityPublicKey": "base64-encoded-public-key",
  "timestamp": 1234567890,
  "signature": "signature-of-timestamp"
}
```

### Messages

All message endpoints require `Authorization: Bearer <JWT>` header.

**Send Message**
```
POST /v1/messages/send
{
  "recipientId": "recipient-public-key",
  "blob": { ... }, // Encrypted message
  "signature": "signature-of-blob"
}
```

**Get Inbox**
```
GET /v1/messages/inbox?limit=50&offset=0
```

**Stream Messages (SSE)**
```
GET /v1/messages/stream
```

**Delete Message**
```
DELETE /v1/messages/:messageId
```

### Profile

**Get Own Profile**
```
GET /v1/profile/me
```

**Get User Profile**
```
GET /v1/profile/:identityPublicKey
```

**Update Profile**
```
POST /v1/profile/update
{
  "profilePublicKey": "new-profile-key",
  "profileKeySignature": "signature-by-identity-key",
  "encryptedProfile": { ... },
  "timestamp": 1234567890,
  "signature": "signature-of-request"
}
```

## Testing

```bash
# Run all tests
yarn test

# Watch mode
yarn test:watch

# Type check
yarn build
```

## Security

- All messages must be signed by the sender's identity key
- Profile keys must be signed by the identity key
- Timestamps are checked to prevent replay attacks (5-minute window)
- JWTs expire after 30 days
- Messages auto-delete after 30 days

## Development

### Project Structure

```
sources/
├── api/              # Fastify routes and API setup
│   ├── routes/v1/   # API endpoints
│   ├── auth.ts      # Authentication middleware
│   └── sse.ts       # Server-Sent Events
├── eventbus/        # Redis-based event distribution
│   ├── eventBus.ts
│   ├── sequenceCounter.ts
│   └── types.ts
├── utils/           # Utilities and helpers
│   ├── crypto.ts    # NaCl signature verification
│   ├── jwt.ts       # JWT generation/verification
│   └── sync.ts      # InvalidateSync helper
├── workers/         # Background workers
│   └── cleanupWorker.ts
├── db.ts            # Prisma client
├── events.ts        # EventBus instance
├── log.ts           # Logging
└── main.ts          # Entry point
```

## License

MIT
