# Identity

The identity domain owns application-facing account custody and, later, the
exact-key identity directory. Raw Ed25519/X25519 operations remain in
`sources/crypto`; the account-secret module composes those roots with local
password protection without storing anything inside Murmur.

```text
identity/
  accountSecret/   generated secret + password -> encrypted identity root
  index.ts         identity-domain public surface
```

The relay, device roster, and MLS session state are outside this module. An
account-secret restore yields only the identity key pair; it never restores or
replicates ratchets.

## Exports

### Account secret

- `createAccountSecret(identity: IdentityKeyPair, password: string): Promise<CreatedAccountSecret>`
  creates application-owned recovery material for one identity root.
- `unlockAccountSecret(blob: string, generatedSecret: string, password: string): Promise<IdentityKeyPair>`
  unlocks the same identity only when both inputs authenticate.
- `rewrapAccountSecret(blob: string, generatedSecret: string, currentPassword: string, newPassword: string): Promise<string>`
  changes the password locally without changing the generated string.

### Exported types

- `CreatedAccountSecret` — the generated string and opaque encrypted blob.
