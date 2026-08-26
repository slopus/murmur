# Private-group state implementation

- `credentialAuthority.ts` adapts the existing keyed issuer and presentation
  verifier to byte-only service callbacks.
- `recordCodec.ts` defines canonical revision encoding, metadata AEAD, HMAC
  authentication, and MLS logical-roster binding.
- `privateGroupStateClient.ts` obtains credentials and tokens, constructs and
  verifies records, and tracks one rollback-protected local revision tip.
- `httpPrivateGroupStateTransport.ts` performs the bounded HTTP flow and
  validates canonical UUIDv7 response metadata.

```text
session snapshot -> encrypted roster + sealed metadata -> HMAC -> revision hash
service response -> HMAC -> decrypt -> MLS roster equality -> chain-tip update
```
