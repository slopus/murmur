# Discovery implementation

`discoveryCodec.ts` uses domain-separated canonical JSON around RFC 9420 KeyPackage
bytes. Parsing is exact and verifies the outer identity signature, every
KeyPackage signature and lifetime, identity binding, uniqueness, and size
bounds.

```text
strict JSON -> canonical public keys -> KeyPackage verification -> signature
```

`discoveryHttpTransport.ts` uploads exact signed bytes to the relay's
five-minute cache and verifies the SHA-256 digest on both upload and download:

```text
bundle bytes -> POST -> 32-byte digest -> GET -> digest check -> bundle parser
```
