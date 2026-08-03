# Direct chat

`DirectChat` is the browser-safe text-message engine over an existing
`MurmurClient`, `FriendBook`, and `MurmurStore`. It owns pairwise topics,
recipient/self envelopes, replay records, cursors, retained send decisions,
pending exact events, and bounded quarantine metadata. Applications own chat,
message, UI, delivery presentation, and read-state tables through atomic
callbacks.

```text
sendText
   |-- recipient-sealed event payload + permanent recipient element
   `-- self-sealed permanent element (different bound ID)

sync/loadTopic
   -> authenticate sender and pairwise topic
   -> collapse relay/copy duplicates by logical message ID
   -> application callback + replay marker + cursor (one transaction)
```

The public send API accepts only text, an optional 24-byte canonical base64url
ID, and an optional `sentAt`. Existing version-one attachment descriptors remain
decodable for history compatibility, but this engine cannot create attachment
messages.

`sendText()` persists the logical message and pending event before publication,
so a thrown publication error can still mean "durably queued." Retrying the
same caller ID resumes it. Pending events older than the relay timestamp window
are atomically replaced with freshly signed, content-equivalent events; stable
list IDs preserve logical idempotency across that replacement.

Removed friends remain subscribed so relay cursors stay gapless. New traffic
from them is authenticated, replay-marked, quarantined, and advanced without
reaching the application callback. Re-adding the authenticated profile
reactivates future delivery without deleting identity history.
