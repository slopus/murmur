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
  "profileSecretKey": "base64url-no-padding",
  "attachments": {
    "report.pdf": {
      "hash": "sha256-hex-of-encrypted-bytes",
      "iv": "base64",
      "key": "base64"
    }
  }
}
```

Notes:

- `text` is required.
- `profileSecretKey` is the sender's profile secret key (base64url, no padding),
  included so a recipient can resolve the sender profile if not already known.
- `attachments` is optional. Each entry maps a filename (no path) to the
  AES-GCM parameters for the encrypted attachment bytes:
  - `hash`: SHA-256 of the encrypted bytes (hex).
  - `iv`: AES-GCM IV (base64).
  - `key`: AES-GCM key (base64).
- Legacy payloads may be a raw UTF-8 string; if JSON parsing fails, the client
  treats the plaintext as text.

## 2) Protocol Message (encrypted blob content)

The application payload is encrypted via Double Ratchet. The resulting protocol
message is JSON-encoded and then base64-encoded for transport.

Protocol messages always use `type: "message"`. Pre-key fields live under
`init` when establishing a new session.

### Pre-key Message

```json
{
  "type": "message",
  "init": {
    "ephemeralKey": "base64",
    "preKey": "base64",
    "oneTimePreKey": "base64"
  },
  "attachments": {
    "sha256-hex": "base64(encrypted-bytes)"
  },
  "ratchetKey": "base64",
  "previousChainLength": 0,
  "messageNumber": 0,
  "ciphertext": "base64"
}
```

### Regular Message

```json
{
  "type": "message",
  "attachments": {
    "sha256-hex": "base64(encrypted-bytes)"
  },
  "ratchetKey": "base64",
  "previousChainLength": 0,
  "messageNumber": 0,
  "ciphertext": "base64"
}
```

Field details:

- `init.ephemeralKey`: X25519 public key (base64).
- The sender identity DH public key is derived by the receiver from the sender identity signing key (`ed25519.utils.toMontgomery`).
- `init.preKey`: recipient prekey public key used for X3DH (required for pre-key messages).
- `init.oneTimePreKey`: recipient one-time prekey public key used for X3DH (optional).
- The presence of `init` indicates a pre-key message.
- `ratchetKey`: current Double Ratchet public key (X25519, base64).
- `previousChainLength`, `messageNumber`: chain counters for the Double Ratchet.
- `ciphertext`: base64-encoded ChaCha20-Poly1305 ciphertext + auth tag.
- `attachments`: optional map of `sha256(encrypted_bytes)` (hex) to the
  AES-GCM encrypted bytes (base64). Filenames are only present inside the
  encrypted payload.

## Algorithms

### Pre-key Message Encryption (sender)

1. Fetch recipient prekey bundle from server and verify the bundle signature.
2. The receiver will derive the sender identity DH key from the sender Ed25519 public key.
3. Run X3DH (sender side) using:
   - Alice identity DH keypair (derived from her Ed25519 identity key)
   - Bob prekey (from bundle)
   - Optional Bob one-time prekey (from bundle)
4. Initialize Double Ratchet (Alice) with the X3DH shared secret and Bob's prekey public key.
5. Ratchet encrypt the plaintext to get:
   - Header fields: `ratchetKey`, `previousChainLength`, `messageNumber`
   - Ciphertext bytes
6. Build protocol message JSON with:
   - `type: "message"`
   - `init` containing `ephemeralKey`, `preKey`, and optional `oneTimePreKey` (from bundle)
   - `attachments` map (if any)
   - `ratchetKey`, `previousChainLength`, `messageNumber`
   - `ciphertext` (base64)
7. Base64-encode the JSON to create the server `blob`.
8. Sign `blobBytes || messageIdBytes` with Alice's Ed25519 identity key.

### Pre-key Message Decryption (receiver)

1. Verify the server signature over `blobBytes || messageIdBytes` using the sender identity key.
2. Decode and parse the protocol message JSON from the `blob`.
3. Look up `init.preKey` (and optional `init.oneTimePreKey`) in the local key store to find the matching private keys.
4. Derive Alice identity DH public key from her Ed25519 public key.
5. Run X3DH (receiver side) using:
   - Bob identity DH keypair
   - Bob prekey private key
   - Optional Bob one-time prekey private key
   - Alice derived identity DH key and `init.ephemeralKey`
6. Initialize Double Ratchet (Bob) with the X3DH shared secret and Bob's prekey keypair.
7. Build the internal header from `ratchetKey`, `previousChainLength`, `messageNumber`.
8. Ratchet decrypt the ciphertext to recover plaintext.

### Regular Message Encryption (sender)

1. Use the existing Double Ratchet session for the recipient.
2. Ratchet encrypt the plaintext to get:
   - `ratchetKey`, `previousChainLength`, `messageNumber`
   - Ciphertext bytes
3. Build protocol message JSON with:
   - `type: "message"`
   - `attachments` map (if any)
   - `ratchetKey`, `previousChainLength`, `messageNumber`
   - `ciphertext` (base64)
4. Base64-encode the JSON to create the server `blob`.
5. Sign `blobBytes || messageIdBytes` with the sender identity key.

### Regular Message Decryption (receiver)

1. Verify the server signature over `blobBytes || messageIdBytes` using the sender identity key.
2. Decode and parse the protocol message JSON from the `blob`.
3. Use the existing Double Ratchet session for the sender.
4. Build the internal header from `ratchetKey`, `previousChainLength`, `messageNumber`.
5. Ratchet decrypt the ciphertext to recover plaintext.

### Double Ratchet Header (internal)

The header is 44 bytes:

- 32 bytes: DH ratchet public key (X25519)
- 4 bytes: previous chain length (uint32, big-endian)
- 4 bytes: message number (uint32, big-endian)
- 4 bytes: reserved (zero)

The header bytes are derived from the ratchet fields and authenticated as
associated data for the ciphertext.

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
