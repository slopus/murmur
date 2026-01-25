# Security Notes

This document summarizes the security model and limitations of Murmur.

## Threat Model

Murmur is designed so the server can route messages without reading content.
It assumes:

- The server is untrusted with respect to message contents.
- Clients protect their local databases and key material.
- Contacts exchange profile secrets out-of-band.

## What the Server Sees

- Sender and recipient identity keys (base64).
- Encrypted message blobs and signatures.
- Message timing, size, and delivery metadata.
- Encrypted profiles and profile key signatures.

The server never sees message plaintext or decrypted profiles.

## Authentication and Integrity

- All sensitive API requests are signed with Ed25519 identity keys.
- Message blobs are signed over `blobBytes || messageIdBytes`.
- Profiles are signed by identity keys to prevent spoofing.

## Session Security

- X3DH establishes a shared secret with signed prekeys.
- Double Ratchet provides forward secrecy and break-in recovery.
- One-time prekeys are supported but may be reused if necessary.

## Attachments

- Each attachment uses a unique AES-256-GCM key and IV.
- Hashes of encrypted bytes prevent tampering.
- Filenames are only present inside the encrypted payload.

## Local Storage

SQLite stores:

- Identity keys and ratchet state.
- Profile secret keys.
- Encrypted messages and attachments.

Treat the local database as sensitive and protect it at rest.

## Hooks

`verify-message` hooks run local commands with access to decrypted content.
Only install hooks you trust. Hook failures reject incoming messages.

## Limitations

- Metadata (sender/recipient, timestamps) is visible to the server.
- Compromised endpoints can read plaintext.
- Realtime notifications are hints; messages are fetched via inbox sync.
