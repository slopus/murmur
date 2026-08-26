# Delivery

The delivery domain defines sender-signed opaque multicast, recipient-signed
queue reads and acknowledgements, ordered inbox pages, continuity metadata,
polling, SSE, and negotiated WebSocket transports.

`InboxProcessor` commits protocol effects, replay markers, rejection records,
and queue cursor progress in one store transaction before acknowledgement.
Terminal malformed items are isolated so later queue work can continue.

Applications may use `HttpDeliveryTransport`, `WebSocketDeliveryTransport`, or
provide the exact `DeliveryTransport` seam. Every page and stream record carries
required sequence and continuity fields.

Every delivery signs the account that owns its outbound relay state. Direct
deliveries sign an exact recipient set. Ongoing session deliveries instead name
the owner/session, leave recipients empty, and sign relay-visible epoch,
coverage, membership, role, and content controls as applicable. Inbox
processing trusts authenticated queue placement for session fanout and still
verifies visible controls against decrypted MLS state.

Both built-in transports decode stale epoch-coverage responses carrying current
rosters and support replay-protected session and terminal account deletion. A
custom transport must expose `deleteSession` and `deleteAccount` for those
operations.

The transport seam optionally exposes current-roster mutation plus directory
upload and exact ticketed claim operations. Both built-in transports implement
all four. A custom transport must implement the directory methods to support
automatic publication, `claimAccount()`, and `rotate()`.
