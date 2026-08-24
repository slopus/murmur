# Relay protocol

Signed identity-addressed multicast deliveries, signed queue reads, signed
monotonic queue acknowledgements, and owner-authorized invitation lifecycle
operations.

```text
sender identity --signs--> delivery(recipient identities, ciphertext, TTL)
recipient identity --signs--> read(after UUIDv7, limit, wait)
recipient identity --signs--> ack(through)
invitation identity --signs--> upload(digest, expiry, revocation public key)
revocation key ------signs--> revoke(digest or all)
```

Each signature has a distinct domain prefix. Ed25519 identities must be
canonical, prime-order public points. Delivery recipients are sorted and unique
so every signer and verifier covers exactly one encoding.

Invitation upload and revocation signatures also use distinct canonical
domains. The invitation identity authorizes only the public revocation key; its
private root never crosses the client boundary. Revocation bodies are
idempotent and reveal no private capability.

Read and acknowledgement signatures are reusable within the configured clock
skew; their timestamps prevent indefinite replay, not one-use replay. TLS is
therefore required to prevent request capture. Reads are harmless to repeat and
acknowledgements are idempotent and monotonic while pending. Once an empty
queue's metadata is reclaimed, a replayed acknowledgement is a no-op and its
response carries no cursor that could appear to regress.

There are no topic descriptors, read capabilities, snapshots, or retained
event-history messages.
