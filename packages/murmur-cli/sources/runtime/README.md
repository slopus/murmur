# CLI runtime

The runtime connects one durable identity to one or more core transports. It
owns contact/profile exchange, direct private messages, encrypted attachments,
manual relay acknowledgement, and local message history.

```text
profile token -> encrypted identity inbox -> ContactBook
message + file -> durable ciphertext outbox -> every relay blob -> exact event
relay delivery -> authenticate -> atomic inbox + replay marker -> acknowledge
```

Outgoing history receives a local monotonic sequence and remains `pending`
until the exact retained event reaches a relay. Blob ciphertext stays durable
until every configured relay has accepted it, preventing a message descriptor
from arriving where its attachment is unavailable. Permanently malformed or
unsupported deliveries enter a bounded quarantine before acknowledgement, so
poison queue pages cannot starve later valid events.

Outgoing attachments are bounded to 64 entries and 64 MiB in aggregate before
encryption, limiting simultaneous plaintext, ciphertext, and SQLite copies.

Group and shared-object state are layered into the same runtime in subsequent
modules; the relay-facing client remains unchanged.
