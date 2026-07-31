# Relay protocol

This module owns the relay wire boundary. It strictly decodes signed writes,
builds their canonical JSON signature preimage, verifies Ed25519, and exposes
opaque byte-oriented domain types.

```text
JSON strings -> strict decode -> Uint8Array fields -> canonical JSON -> Ed25519
```

The relay never decodes `payload`, snapshot bytes, list bytes, or blobs beyond
base64url and size validation.
