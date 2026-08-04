# Sources

```text
index.ts        public root export
murmur/         stateful facade and synchronization
identity/       one-key identity and friend bootstrap/control
mls/            internal RFC 9420 / TreeKEM subset
crypto/         Noble-based identity and sealed boxes
transport/      browser-safe HTTP relay wire implementation
storage/        application persistence boundary
utils/          strict byte and JSON helpers
```

Only `index.ts` is exported by the package. Other modules are internal
implementation boundaries compiled once into `@slopus/murmur`.
