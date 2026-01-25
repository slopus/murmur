# Message Format

This document describes the on-wire message formats used by Murmur.

## Layers

Messages are wrapped in three layers:

1. **Application payload** (plaintext before encryption)
2. **Protocol message** (Double Ratchet output, JSON)
3. **Server envelope** (blob + signature)

## 1) Application Payload (plaintext)

Current payload JSON:

```json
{
  "text": "Hello there",
  "profileSecretKey": "base64url-no-padding"
}
```

Notes:

- `text` is required.
- `profileSecretKey` is the sender's profile secret key (base64url, no padding),
  included so a recipient can resolve the sender profile if not already known.
- Legacy payloads may be a raw UTF-8 string; if JSON parsing fails, the client
  treats the plaintext as text.

## 2) Protocol Message (encrypted blob content)

The application payload is encrypted via Double Ratchet. The resulting protocol
message is JSON-encoded and then base64-encoded for transport.

Protocol messages always use `type: "message"`. Pre-key fields are included
when establishing a new session.

### Pre-key Message

```json
{
  "type": "message",
  "identityDHKey": "base64",
  "ephemeralKey": "base64",
  "signedPreKey": "base64",
  "oneTimePreKey": "base64",
  "header": "base64",
  "ciphertext": "base64"
}
```

### Regular Message

```json
{
  "type": "message",
  "header": "base64",
  "ciphertext": "base64"
}
```

Field details:

- `identityDHKey`, `ephemeralKey`: X25519 public keys (base64).
- `signedPreKey`: recipient signed prekey public key used for X3DH (required for pre-key messages).
- `oneTimePreKey`: recipient one-time prekey public key used for X3DH (optional).
- The presence of `identityDHKey` + `ephemeralKey` indicates a pre-key message.
- Regular messages identify the derived ratchet key via the encoded header's public key.
- `header`: base64-encoded 44-byte Double Ratchet header.
- `ciphertext`: base64-encoded ChaCha20-Poly1305 ciphertext + auth tag.

### Double Ratchet Header (encoded)

The header is 44 bytes:

- 32 bytes: DH ratchet public key (X25519)
- 4 bytes: previous chain length (uint32, big-endian)
- 4 bytes: message number (uint32, big-endian)
- 4 bytes: reserved (zero)

The encoded header bytes are authenticated as associated data for the ciphertext.

### Ciphertext

Ciphertext is produced by ChaCha20-Poly1305. The 12-byte nonce is derived from
the message key via HKDF-SHA-256, so no nonce is transmitted.

## 3) Server Envelope

To send, the client builds:

```json
{
  "messageId": "cuid",
  "recipientId": "base64-identity-key",
  "blob": "base64(protocol_message_json)",
  "signature": "base64"
}
```

Signature:

- Sign Ed25519 over: `blobBytes || messageIdBytes`
- `blobBytes`: base64-decoded `blob`
- `messageIdBytes`: UTF-8 bytes of the message ID
- Signature is base64-encoded

Inbox messages returned by the server include:

```json
{
  "id": "messageId",
  "senderId": "base64-identity-key",
  "blob": "base64(protocol_message_json)",
  "signature": "base64",
  "createdAt": 1710000000000,
  "expiresAt": 1712592000000
}
```
