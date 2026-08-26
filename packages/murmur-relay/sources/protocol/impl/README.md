# Protocol implementation

Strict identity-queue delivery, read, and acknowledgement codecs plus canonical
Ed25519 signing bytes. Every decoder rejects unknown fields and non-canonical
base64url or integer representations.

Only queue protocol messages are encoded in this directory.

```text
JSON delivery/read/ack -> exact decode -> canonical signed bytes -> verify
complete signed delivery -------------------------------> fingerprint
```
