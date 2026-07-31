# Messaging

Direct messages use an ephemeral X25519 sealed box plus an Ed25519 signature
bound to the recipient. They travel on the pairwise shared-secret topic, not a
public identity inbox.

Every sent chat message is also appended as one opaque permanent list element.
`privateMessageListElementId()` derives a stable author-scoped ID from the
application message ID, so retained publication retries cannot append a second
copy. New devices load `readState` and every `readList` page before following
the bounded event log.

`acceptPrivateMessageFromContact()` commits the application record, replay
marker, and optional relay cursor in one `MurmurStore` transaction. It returns
`"opened"` or `"duplicate"`; authenticated same-ID content collisions throw and
leave the cursor unchanged.

Files are AES-256-GCM encrypted before upload. Their secret descriptor appears
only inside encrypted message content.
