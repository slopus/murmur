# Account secret

The account-secret module wraps one 32-byte identity root with two independent
inputs: a generated 256-bit string and a user password. The application owns
the generated string and opaque encrypted blob; Murmur stores neither and has
no server recovery path.

```text
generated string --HKDF-SHA-256--\
                                  +--HKDF-SHA-256--> AES-256-GCM key
user password --------scrypt-----/
                                           |
identity root + future root fields --------+--> base64url blob
```

The blob is a canonical versioned binary envelope encoded once as unpadded
base64url. Its authenticated header fixes the algorithm identifiers, scrypt
parameters, salt, nonce, and ciphertext length. The encrypted payload is an
ordered typed-field sequence: field `1` is the identity root, and later field
numbers can carry additional root material without changing the public blob
contract. Rewrapping preserves that complete payload while rotating the salt,
nonce, and password-derived key component.

## Exports

### Account-secret lifecycle

- `createAccountSecret(identity: IdentityKeyPair, password: string): Promise<CreatedAccountSecret>`
  generates a strong account string and encrypts the identity root.
- `unlockAccountSecret(blob: string, generatedSecret: string, password: string): Promise<IdentityKeyPair>`
  authenticates both factors and reconstructs the identity.
- `rewrapAccountSecret(blob: string, generatedSecret: string, currentPassword: string, newPassword: string): Promise<string>`
  authenticates the existing blob and returns a fresh blob under the new
  password while keeping the generated string.

### Exported types

- `CreatedAccountSecret` — the generated string and opaque application-owned
  blob returned at creation.
