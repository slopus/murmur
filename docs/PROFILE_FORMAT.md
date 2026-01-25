# Encrypted Profile Format

This document describes how Murmur profiles are encrypted, encoded, and verified.

## Overview

Profiles are stored on the server as an encrypted blob. Decryption requires the
profile secret key, which is shared out-of-band (e.g., via contact exchange).

Profile JSON payload:

```json
{
  "firstName": "Alice",
  "lastName": "Smith"
}
```

`lastName` is optional and omitted when undefined.

## Key Material

- **Profile secret key**: 32-byte X25519 private key.
  - Serialized as base64url without padding.
- **Profile public key**: X25519 public key derived from the secret key.
  - Serialized as standard base64.
- **Identity key**: Ed25519 keypair used to sign the profile public key.

## Encryption

1. Serialize the profile JSON to UTF-8 bytes.
2. Derive a 32-byte encryption key using HKDF-SHA-256:
   - IKM: profile secret key
   - Salt: empty (undefined)
   - Info: `"murmur-profile-encryption"`
3. Generate a 12-byte random nonce.
4. Encrypt with ChaCha20-Poly1305.
5. Concatenate `nonce || ciphertext` (ciphertext includes the auth tag).
6. Encode the combined bytes as standard base64.

## Signature

The profile public key is signed by the identity private key to prove ownership:

- Input: raw profile public key bytes.
- Signature: Ed25519, encoded as standard base64.

## Server Fields

The server stores and returns:

- `profilePublicKey`: base64 (standard)
- `profileKeySignature`: base64 (standard)
- `encryptedProfile`: base64 (standard)
- `profileUpdatedAt`: milliseconds since epoch

## Decryption

1. Decode `encryptedProfile` from base64.
2. Split into `nonce` (first 12 bytes) and `ciphertext` (remaining).
3. Re-derive the encryption key via HKDF-SHA-256 (same inputs as above).
4. Decrypt with ChaCha20-Poly1305.
5. Parse the UTF-8 JSON.
