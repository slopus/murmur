# CLI runtime

The runtime connects one durable identity to one or more core transports. It
owns contact/profile/KeyPackage exchange, direct private messages, encrypted
attachments, RFC 9420 groups, manual relay acknowledgement, and local history.

```text
profile token -> encrypted identity inbox -> ContactBook
message + file -> durable ciphertext outbox -> every relay blob -> exact event
relay delivery -> authenticate -> atomic inbox + replay marker -> acknowledge
profile v2 -> signed one-use KeyPackage -> encrypted Welcome
group send/Commit -> exact outbox + next epoch -> publish -> adopt
```

Outgoing history receives a local monotonic sequence and remains `pending`
until the exact retained event reaches a relay. Blob ciphertext stays durable
until every configured relay has accepted it, preventing a message descriptor
from arriving where its attachment is unavailable. Permanently malformed or
unsupported deliveries enter a bounded quarantine before acknowledgement, so
poison queue pages cannot starve later valid events.

Outgoing attachments are bounded to 64 entries and 64 MiB in aggregate before
encryption, limiting simultaneous plaintext, ciphertext, and SQLite copies.

Group creation starts at RFC epoch zero. Add invitations carry an encrypted
Welcome and authenticated external tree inside the existing pairwise direct
channel. Add, Remove, and application messages persist their exact event,
post-ratchet epoch, generation, replay marker, and history atomically before
publication or acknowledgment. Removed clients retain only a topic tombstone
so later ciphertext is drained without retaining or using group secrets.

Shared-object state is layered over the same authenticated group application
channel. Shared text documents persist their deterministic operation log in the
same transaction as the MLS ratchet checkpoint and exact outbox or inbound
replay marker. The relay-facing client remains unchanged.
