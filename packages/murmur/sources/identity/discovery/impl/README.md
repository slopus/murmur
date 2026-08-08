# Discovery implementation

`discoveryCodec.ts` uses domain-separated canonical JSON around RFC 9420 KeyPackage
bytes. Parsing is exact and verifies the outer identity signature, every
KeyPackage signature and lifetime, identity binding, uniqueness, and size
bounds.

```text
strict JSON -> canonical public keys -> KeyPackage verification -> signature
```
