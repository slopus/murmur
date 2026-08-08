# Protocol implementation

Strict identity-queue delivery, read, and acknowledgement codecs plus canonical
Ed25519 signing bytes. Every decoder rejects unknown fields and non-canonical
base64url or integer representations.

```text
JSON delivery/read/ack -> exact decode -> canonical signed bytes -> verify
complete signed delivery -------------------------------> fingerprint
```
