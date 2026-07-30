# Claude Code Project Knowledge

This document contains architectural decisions, implementation patterns, and design philosophy for the Murmur Server project.

## Project Overview

Murmur Server is an encrypted message transfer server using NaCl-based authentication. It provides a secure messaging platform with cryptographic verification of all operations.

## Core Architecture Principles

### 1. Separation of Storage and Delivery

**Messages are stored in PostgreSQL, NOT in Redis.**

- **Storage Layer**: PostgreSQL database (via Prisma ORM)
    - User accounts and profiles
    - Message blobs (encrypted content)
    - All persistent data

- **Delivery Layer**: Redis Streams
    - Inter-node event notifications only
    - Reliable delivery of "new message" events across server instances
    - NOT used for message storage or retrieval

**Key Point**: Reading messages does NOT acknowledge them in Redis. Messages only exist in the database. Redis is purely for notifying nodes about new messages.

### 2. Shutdown and Signal Management

**Central AbortController Pattern**

All async operations use standard `AbortSignal` for graceful shutdown:

```typescript
// shutdown.ts provides global AbortController
const shutdownController = new AbortController();
export function getShutdownSignal(): AbortSignal {
    return shutdownController.signal;
}
```

**No Custom Shutdown Hacks**:

- Don't create custom shutdown callbacks or state management
- Use the centralized `getShutdownSignal()` from shutdown module
- All timing utilities accept `AbortSignal` parameter
- Shutdown triggers on SIGINT/SIGTERM

### 3. Timing Utilities Design

Located in `sources/utils/timing.ts`:

#### `delay(ms: number, signal?: AbortSignal)`

- Standard abortable delay
- Rejects with `DOMException('Delay aborted', 'AbortError')` when signal aborts
- Works without signal for backward compatibility

#### `forever(fn, intervalMs, signal, backoffOptions?)`

- **Runs code with exponential backoff OUTSIDE the loop**
- On error, applies backoff delay before retrying
- On success, waits `intervalMs` before next iteration
- Gracefully exits when signal aborts
- Backoff is applied to error recovery, not to the main loop interval

```typescript
// Good: forever with backoff on errors
await forever(
    async () => await cleanup(),
    60000, // Run every hour on success
    signal,
    {
        initialDelayMs: 1000, // Start with 1s delay on error
        maxDelayMs: 60000, // Max 60s delay on error
        multiplier: 2, // Double delay each retry
    },
);
```

#### `retryWithBackoff(fn, options)`

- Exponential backoff retry logic
- Configurable initial delay, max delay, multiplier
- Respects max attempts
- Aborts immediately when signal triggered

### 4. Worker Patterns

#### Cleanup Worker Design

**Must be a simple function, NOT a class**:

```typescript
// sources/workers/cleanupWorker.ts

export async function startCleanupWorker(): Promise<void> {
    const signal = getShutdownSignal();

    await forever(async () => await cleanup(), CHECK_INTERVAL_MS, signal, {
        /* backoff options */
    });
}
```

**Usage in main.ts**:

```typescript
// Start in background, don't await
startCleanupWorker().catch((err) => {
    log(`Cleanup worker error: ${err}`);
});
```

**No shutdown handler needed** - forever() exits automatically when signal aborts.

### 5. EventBus Implementation

Located in `sources/eventbus/eventBus.ts`:

**Consumer Groups with cuid2**:

- Consumer names generated with `cuid2.createId()` (async import)
- Each server instance has unique consumer name
- Enables distributed processing across multiple nodes

**Hard Crash on Consumer Group Deletion**:

```typescript
if (error.message && error.message.includes("NOGROUP")) {
    log(`FATAL: Consumer group deleted!`);
    process.exit(1); // Hard crash - don't try to recover
}
```

**Read Loop with forever**:

```typescript
private async readLoop(signal: AbortSignal): Promise<void> {
    await forever(async () => {
        const results = await this.client.xreadgroup(/* ... */);
        // Process messages
    }, 0, signal);  // No delay - XREADGROUP blocks internally
}
```

### 6. Authentication System

**Two-Tier Token System**:

- **Access Tokens**: Ephemeral, 1-hour TTL
    - Created with `createEphemeralTokenGenerator` from privacy-kit
    - Used for API authentication
    - Short-lived for security

- **Refresh Tokens**: Persistent, long-lived
    - Created with `createPersistentTokenGenerator` from privacy-kit
    - Used to get new access tokens
    - Stored securely by client

**Public Key Management**:

- Verifier takes public key directly from generator
- No need for external public key configuration
- `verifier.publicKey = generator.publicKey`

**Endpoints**:

- `/v1/auth/register` - Returns both tokens
- `/v1/auth/login` - Returns both tokens
- `/v1/auth/refresh` - Takes refresh token, returns new access token

### 7. Cryptographic Verification

**NaCl Ed25519 Signatures**:

All operations are verified using Ed25519 signatures (via `@noble/curves`).
Most requests sign `JSON.stringify(payload)`, while message sends sign raw blob bytes
concatenated with UTF-8 bytes of `messageId`.

**Message Integrity**:

- Message signatures include BOTH blob and messageId
- Prevents tampering and replay attacks
- Message IDs must be valid cuid2 format

**Profile Security**:

- Profile encryption keys signed by identity key
- Prevents unauthorized profile key changes

**PreKey System** (Signal Protocol):

- Signed prekeys and one-time prekeys stored in unified `PreKey` table
- `oneTime` flag distinguishes between signed (false) and one-time (true) prekeys
- PreKeys permanently allocated to users who claim them (not deleted)
- Allocation tracking: `allocatedTo` and `allocatedAt` fields
- Signed prekeys can be reused for same requester
- One-time prekeys allocated once, subsequent fetches return null
- All prekeys signed by owner's identity key

### 8. Testing Philosophy

**Comprehensive Unit Tests**:

- Tests cover crypto, JWT, timing, and sync helpers
- All new features should include tests
- Focus on edge cases and error scenarios

**Test Organization**:

```
sources/utils/
├── timing.test.ts      # 15 tests - delay, forever, backoff
├── jwt.test.ts         # 14 tests - refresh token flow
├── crypto.test.ts      # 10 tests - signature verification
├── sync.test.ts        # 5 tests - InvalidateSync helper
└── trimIndent.test.ts  # 5 tests - string utilities
```

## Common Patterns

### 1. Starting Background Workers

```typescript
// DON'T await - let it run in background
startCleanupWorker().catch((err) => {
    log(`Worker error: ${err}`);
});
```

### 2. Implementing Loops with Graceful Shutdown

```typescript
import { forever } from "@/utils/timing";
import { getShutdownSignal } from "@/shutdown";

const signal = getShutdownSignal();

await forever(
    async () => {
        // Your work here
    },
    intervalMs,
    signal,
    {
        // Optional backoff on errors
        initialDelayMs: 100,
        maxDelayMs: 30000,
        multiplier: 2,
    },
);
```

### 3. Implementing Retry Logic

```typescript
import { retryWithBackoff } from "@/utils/timing";
import { getShutdownSignal } from "@/shutdown";

const result = await retryWithBackoff(async () => await riskyOperation(), {
    signal: getShutdownSignal(),
    initialDelayMs: 100,
    maxDelayMs: 30000,
    multiplier: 2,
    maxAttempts: 5,
});
```

### 4. Implementing Abortable Delays

```typescript
import { delay } from "@/utils/timing";
import { getShutdownSignal } from "@/shutdown";

try {
    await delay(5000, getShutdownSignal());
} catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
        // Shutdown requested
        return;
    }
    throw error;
}
```

## Anti-Patterns (Don't Do This)

### ❌ Custom Shutdown State Management

```typescript
// BAD - don't create custom shutdown tracking
let isShuttingDown = false;
const shutdownCallbacks = [];

export function signalShutdown() {
    isShuttingDown = true;
    // ...
}
```

**Instead**: Use centralized `getShutdownSignal()` from shutdown module.

### ❌ Class-Based Workers with start/stop Methods

```typescript
// BAD - complex class with state management
export class CleanupWorker {
    async start() {
        /* ... */
    }
    async stop() {
        /* ... */
    }
}
```

**Instead**: Simple function that uses `forever()` with AbortSignal.

### ❌ Storing Messages in Redis

```typescript
// BAD - don't store messages in Redis
await redis.set(`message:${id}`, JSON.stringify(message));
```

**Instead**: Store in PostgreSQL via Prisma, use Redis only for notifications.

### ❌ Manual Backoff in Loops

```typescript
// BAD - manually implementing backoff
while (true) {
    try {
        await work();
        delay = 100;
    } catch (error) {
        delay = Math.min(delay * 2, 30000);
        await sleep(delay);
    }
}
```

**Instead**: Use `forever()` with `backoffOptions` parameter.

### ❌ Acknowledging Messages on Read

```typescript
// BAD - don't acknowledge messages when reading from DB
const messages = await db.message.findMany();
await redis.xack("messages", group, messageIds);
```

**Instead**: Messages in DB are independent from Redis events.

## Dependencies and Versions

### Core Dependencies

- **Fastify**: Web framework
- **Prisma**: ORM for PostgreSQL
- **ioredis**: Redis client
- **privacy-kit**: JWT token generation (ephemeral + persistent)
- **tweetnacl**: NaCl cryptography
- **@paralleldrive/cuid2**: Collision-resistant IDs
- **zod**: Runtime type validation

### Development

- **TypeScript**: Type safety
- **Vitest**: Testing framework
- **tsx**: TypeScript execution

## Database Schema

### User

- `id`: Identity public key (base64 with padding)
- `profilePublicKey`: Profile encryption key (base64 with padding)
- `profileKeySignature`: Signature of profile key by identity
- `encryptedProfile`: Encrypted profile bytes (base64 in API)
- `profileUpdatedAt`: Last profile update
- `createdAt`: Account creation

### Message

- `id`: cuid2 message ID (primary key)
- `senderId`: Sender's identity public key
- `recipientId`: Recipient's identity public key
- `blob`: Encrypted message bytes (base64 in API)
- `signature`: Message signature
- `createdAt`: Message creation
- `expiresAt`: Expiration date (createdAt + 30 days)

## Environment Configuration

### Required Variables

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string (default: redis://localhost:6379)
- `JWT_SEED`: Secret seed for JWT generation

### Optional Variables

- `PORT`: HTTP server port (default: 3000)
- `NODE_ENV`: Environment (development/production)

## Deployment Considerations

### Multi-Node Deployment

- Each node runs independent EventBus consumer
- Consumer groups ensure messages processed only once across all nodes
- Redis Streams provide at-least-once delivery semantics with consumer group acknowledgments
- Nodes can be added/removed without coordination

### Database

- Use connection pooling for PostgreSQL
- Regular backups of PostgreSQL data
- Messages auto-delete after 30 days via cleanup worker

### Redis

- Redis Streams require persistence (AOF or RDB)
- Consumer group state stored in Redis
- If Redis restarts, consumer groups recreated automatically

### Monitoring

- Watch for consumer group deletion (causes process.exit(1))
- Monitor message expiration cleanup success rate
- Track SSE connection counts and durations

## Future Enhancements

Potential areas for improvement:

1. **Read Receipts**: Track message read status
2. **Message Encryption**: End-to-end encryption helpers
3. **Group Messaging**: Multi-recipient message support
4. **WebSocket Support**: Optional alternative to SSE
