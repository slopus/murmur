# `@murmur/relay`

A deliberately dumb Murmur relay. It authenticates transport envelopes, fans
them out to explicit recipients or topic subscribers, retains one queue per
recipient until acknowledgement, and stores content-addressed ciphertext blobs.

The package contains no HTTP, database, chat, profile, document, or MLS logic.
Host adapters provide a `RelayStore`, so the same service can run in a Node
process or a Cloudflare Durable Object.
