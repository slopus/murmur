# Relay protocol

Signed identity-addressed multicast deliveries, signed queue reads, and signed
monotonic queue acknowledgements.

```text
sender identity --signs--> delivery(recipient identities, ciphertext, TTL)
recipient identity --signs--> read(after UUIDv7, limit, wait)
recipient identity --signs--> ack(through)
```

Each signature has a distinct domain prefix. Ed25519 identities must be
canonical, prime-order public points. Delivery recipients are sorted and unique
so every signer and verifier covers exactly one encoding.

Read and acknowledgement signatures are reusable within the configured clock
skew; their timestamps prevent indefinite replay, not one-use replay. TLS is
therefore required to prevent request capture. Reads are harmless to repeat and
acknowledgements are idempotent and monotonic while pending. Once an empty
queue's metadata is reclaimed, a replayed acknowledgement is a no-op and its
response carries no cursor that could appear to regress.

There are no topic descriptors, read capabilities, snapshots, or retained
event-history messages.
