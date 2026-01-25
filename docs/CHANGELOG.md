# Changelog

## [2.0.0] - 2026-01-23

### Breaking Changes

- **JWT Implementation**: Replaced `jsonwebtoken` with `privacy-kit`
  - Access tokens now use a configurable TTL (default 24h)
  - Automatic refresh token support included
  - Requires `JWT_SEED` environment variable
  - Generate a seed with `yarn tsx scripts/generateKeys.ts` (only `JWT_SEED` is used by the server)

- **Message ID Format**: Messages must now include sender-provided cuid2 IDs
  - `messageId` field is now required in send message requests
  - IDs must be valid cuid2 format (validated on server)
  - Repeat protection: duplicate message IDs are rejected

- **Message Signatures**: Signature format changed
  - Signatures must now include both blob bytes AND message ID bytes
  - Format: `signature = sign(concat(blobBytes, utf8(messageId)))`
  - Prevents message ID tampering

- **EventBus Architecture**: Migrated from Redis pub/sub to Redis Streams
  - Reliable event delivery across nodes
  - Consumer groups for distributed processing
  - Removed sequence numbers (messages identified by cuid2)

### Added

- **Message Acknowledgment**: New `/v1/messages/ack` endpoint
  - Clients acknowledge messages to delete them from the database
  - Enables explicit inbox cleanup

- **Channel-Based Routing**: Events now published to channels
  - Format: `user:userId` for user events, `global` for system events
  - Enables future sharding capabilities

- **Repeat Protection**: Duplicate message IDs are rejected
  - Unique constraint on message ID in database
  - Prevents replay attacks with same message ID

### Security Improvements

- privacy-kit JWT with automatic refresh token rotation
- Message ID validation (must be valid cuid2)
- Signature includes message ID to prevent tampering
- 24-hour access token expiration (more secure than 30 days)

### Reliability Improvements

- Redis Streams provide durable event notifications across nodes
- No message loss on Redis restart
- Consumer groups coordinate multi-server processing
- Explicit inbox cleanup via `/v1/messages/ack`

### Removed

- `UserSequence` table (no longer needed)
- Sequence numbers from EventBus
- `sequenceCounter.ts` module
- `jsonwebtoken` and `@types/jsonwebtoken` dependencies

### Migration Guide

#### For Server Operators

1. Generate new JWT keys:
   ```bash
   yarn tsx scripts/generateKeys.ts
   ```

2. Update `.env` file with new key:
   ```
   JWT_SEED=<generated-seed>
   ```

3. Remove old `JWT_SECRET` environment variable

4. Run database migrations:
   ```bash
   yarn prisma migrate deploy
   ```

#### For Client Developers

1. **Message Sending**: Include `messageId` in send requests
   ```typescript
   import { createId } from '@paralleldrive/cuid2';

   const messageId = createId();
   const blobBytes = /* encrypted message bytes */;
   const blob = encodeBase64(blobBytes);
   const messageIdBytes = new TextEncoder().encode(messageId);
   const messageToSign = new Uint8Array(blobBytes.length + messageIdBytes.length);
   messageToSign.set(blobBytes, 0);
   messageToSign.set(messageIdBytes, blobBytes.length);
   const signatureBytes = nacl.sign.detached(messageToSign, privateKey);

   await fetch('/v1/messages/send', {
     method: 'POST',
     body: JSON.stringify({
       messageId,
       recipientId,
       blob,
      signature: encodeBase64(signatureBytes)
     })
   });
   ```

2. **Message Acknowledgment**: Acknowledge messages after successful delivery
   ```typescript
   await fetch('/v1/messages/ack', {
     method: 'POST',
     headers: { Authorization: `Bearer ${token}` },
     body: JSON.stringify({ messageIds: [messageId] })
   });
   ```

3. **Token Refresh**: Handle access token expiration with refresh tokens
   - privacy-kit tokens automatically handle refresh
   - Re-authenticate if refresh token expires

### Testing

Tests updated:
- JWT tests now use async/await
- Tests initialize JWT before use

## [1.0.0] - 2026-01-22

Initial release with NaCl-based authentication and Redis pub/sub EventBus.
