# Murmur Protocol

This document explains how Murmur establishes sessions and formats messages at a
protocol level. For exact wire formats, see:

- `docs/MESSAGE_FORMAT.md`
- `docs/PROFILE_FORMAT.md`

## Key Material

Murmur uses two key families:

- Identity keys: Ed25519 signing keys (32-byte public key).
- DH keys: X25519 keys for Diffie-Hellman (32-byte public key).

The sender's identity DH key is derived from the Ed25519 identity key using
the standard ed25519-to-x25519 conversion (`ed25519.utils.toMontgomery`).

Profile keys are separate from identity keys. The profile secret key is an
X25519 private key used only for profile encryption/decryption and can be
shared out-of-band to add contacts.

## Encodings

- API requests/responses use standard base64 (with padding).
- Profile secret keys are base64url without padding in payloads.
- The CLI displays IDs in base58 for human sharing; it converts to base64
  internally when calling the API.

## Sessions (X3DH + Double Ratchet)

### Prekey Bundle

Each account uploads:

- Signed prekey: long-lived X25519 public key signed by the identity key.
- One-time prekeys: optional X25519 keys, signed by the identity key.

### Session Initialization (Sender)

When Alice has no session with Bob:

1. Fetch Bob's prekey bundle from the server.
2. Verify the signed prekey signature using Bob's identity public key.
3. Generate an ephemeral X25519 keypair.
4. Run X3DH with:
   - Alice identity DH key (derived from Ed25519).
   - Alice ephemeral key.
   - Bob signed prekey.
   - Optional Bob one-time prekey.
5. Initialize Double Ratchet with the X3DH shared secret.
6. Encrypt the application payload and send a prekey message containing the
   `init` block with the ephemeral key and the prekeys used.

### Session Initialization (Receiver)

When Bob receives a prekey message:

1. Verify the message signature (Ed25519).
2. Parse `init` to identify which prekeys were used.
3. Load matching private keys from local storage.
4. Derive Alice identity DH public key from her Ed25519 key.
5. Run X3DH and initialize Double Ratchet.
6. Decrypt the ciphertext to obtain the application payload.

### Regular Messages

Once a session exists, messages omit `init` and are encrypted/decrypted using
the existing Double Ratchet state.

## Application Payload

The plaintext payload is JSON with:

- `text`: the message body.
- `profileSecretKey`: base64url (no padding) of the sender's profile secret.
- `attachments`: optional per-file metadata.

Legacy clients may send raw text; if JSON parsing fails, the plaintext is used.

## Attachments

Attachments are encrypted and transported in two parts:

1. Encrypted bytes are stored in the protocol `attachments` map:
   `sha256(ciphertext_bytes) -> base64(ciphertext_bytes)`.
2. The application payload contains per-file metadata:
   `{ fileName: { hash, iv, key } }`.

Each attachment uses AES-256-GCM with a random 12-byte IV. The filename appears
only inside the encrypted payload.

On receive, the client verifies the hash, decrypts the ciphertext, and stores
the encrypted bytes locally. If attachment validation fails, the message is
ignored.

## Signatures and Envelope

Messages are sent to the server as:

```json
{
  "messageId": "cuid2",
  "recipientId": "base64-identity-key",
  "blob": "base64(protocol_message_json)",
  "signature": "base64"
}
```

The signature is Ed25519 over `blobBytes || messageIdBytes`.

## Acknowledgments

- Server acknowledgments delete messages from the server (`/v1/messages/ack`).
- Client acknowledgments mark messages as read locally.

## Feeds

Feeds are persistent encrypted timelines owned by a single identity.

### Feed Key Derivation

For epoch `N`, the owner derives:

- `feedKey = HKDF(identityPrivateKey, salt=feedId, info="murmur-feed-key:N")`

The owner therefore never needs to upload or persist raw feed keys.

### Metadata

Feed metadata (`name`, optional `description`) is encrypted with a separate
owner-only key derived from the identity private key and `feedId`.

### Member Key Distribution

Members receive epoch keys through a sealed-box style envelope:

1. Generate an ephemeral X25519 keypair.
2. Compute DH with the recipient's X25519 identity key (derived from Ed25519).
3. HKDF the shared secret into an AES-256-GCM wrapping key.
4. Encrypt the raw 32-byte feed key.
5. Transmit `ephemeralPublic || iv || ciphertext`.

### Feed Item Payload

Feed items are encrypted JSON:

```json
{
  "text": "Post body",
  "attachments": {
    "file.txt": {
      "hash": "sha256-hex",
      "iv": "base64",
      "key": "base64",
      "ciphertext": "base64"
    }
  }
}
```

The server stores the encrypted blob and an Ed25519 signature over
`blobBytes || itemIdBytes`.

### Rotation

Membership changes rotate the epoch. The owner removes members, derives the
next epoch key locally, encrypts it to all remaining members, and the server
updates `currentEpoch`.

## Realtime Notifications

Realtime uses SSE. The server emits `message:new` events containing `messageId`.
Clients treat the event as a hint and call `sync` to fetch messages.

Feed timeline updates emit `feed:new_item` with `feedId` and `itemId`.

## Hooks (message)

Incoming and outgoing messages run local `message` hooks. Each hook receives a
temp folder containing `message.json` and any attachments. If a hook fails, the
message is rejected (outgoing is blocked; incoming triggers a failure notice).
