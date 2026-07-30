# `@murmur/relay-node`

Low-cost durable host adapters for the dumb Murmur relay. SQLite stores opaque
signed events, per-recipient delivery queues, replay IDs, subscriptions, and
ciphertext blobs in one local file. The bundled executable is the default
low-cost rendezvous host: it enables credential-free browser CORS, bounds HTTP
work in the runtime-neutral relay, and prunes inactive topics hourly.
