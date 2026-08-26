# Protocol implementation

Strict identity-queue delivery, read, acknowledgement, terminal-deletion, and
directory codecs plus canonical Ed25519 signing bytes. Every decoder rejects
unknown fields and non-canonical base64url or integer representations.

`directoryCodec.ts` parses account-signed prekey uploads, device-signed spent
notifications, opaque ticket claims, and one stable known-or-unknown claim
response envelope.

```text
JSON delivery/read/ack/directory -> exact decode -> canonical bytes -> verify
complete signed delivery ---------------------------------------> fingerprint
```
