# Chat domain

This directory contains the small public surface for generic conversations.
Secondary binary codecs, persistence, attachment cryptography, and convergence
mechanics live under `impl`.

```text
ChatService
  |-- opaque Murmur group descriptor and frames
  |-- durable outbox and sequence projection
  `-- encrypted, independently authenticated chunks
```
