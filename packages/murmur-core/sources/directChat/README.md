# Direct chat

`DirectChat` is the browser-safe message and attachment engine over an existing
`MurmurClient`, `FriendBook`, and `MurmurStore`. It owns pairwise topics,
recipient/self envelopes, replay records, cursors, retained send decisions,
pending exact events, and bounded quarantine metadata. Applications own chat,
message, UI, delivery presentation, and read-state tables through atomic
callbacks.

```text
sendMessage
   |-- encrypt files and transactionally retain ciphertext outbox
   |-- upload every blob to a relay before that relay sees the event
   |-- recipient-sealed event payload + permanent recipient element
   `-- self-sealed permanent element (different bound ID)

sync/loadTopic
   -> authenticate sender and pairwise topic
   -> collapse relay/copy duplicates by logical message ID
   -> application callback + replay marker + cursor (one transaction)
```

`sendMessage()` accepts text plus at most 64 plaintext `Uint8Array`
attachments. MIME defaults to `application/octet-stream`. Documents
(non-`image/*`) are limited to exactly 10 MiB of plaintext, photos retain the
64 MiB encrypted relay cap, and all attachments together are limited to 64 MiB
of plaintext. Filenames and MIME values use the same strict hand-written codec
validation as authenticated descriptors. `sendText()` keeps its original
signature and delegates with an empty attachment array.

The canonical send record retains descriptor metadata, encrypted-message
fingerprint, and plaintext content hashes for caller-ID collision detection.
The outbox retains exact ciphertext and per-relay blob/event progress in the
same transaction as consumer callback state. A thrown publication error can
therefore still mean "durably queued." Retries re-upload idempotently after an
ambiguous response, never expose an event on a relay before all of its blobs
exist there, and delete local ciphertext only after every still-configured
relay accepts both blobs and event. Relays removed from configuration no longer
poison or retain an otherwise completed outbox. Stale events are atomically
replaced with freshly signed, content-equivalent events; stable list IDs
preserve logical idempotency.

`fetchAttachment()` is stateless and content-addressed. It applies document
policy before network work, asks the client for the exact expected ciphertext
length, and verifies SHA-256, AES-GCM associated data, and plaintext length.
Typed errors distinguish policy refusal, unavailable ciphertext, and
integrity/tamper failure. `attachmentPolicy()` exposes the authenticated
metadata decision without downloading. Oversize authenticated documents still
enter history; only their fetch is blocked.

Removed friends remain subscribed so relay cursors stay gapless. New traffic
from them is authenticated, replay-marked, quarantined, and advanced without
reaching the application callback. Re-adding the authenticated profile
reactivates future delivery without deleting identity history.
