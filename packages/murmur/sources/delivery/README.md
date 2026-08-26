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

Session deliveries carry a signed nullable owner/session pair used only for
terminal relay cleanup. Both built-in transports support account-signed,
replay-protected session deletion; a custom transport must expose
`deleteSession` before owner deletion is available.

The transport seam optionally exposes current-roster mutation plus directory
upload and exact ticketed claim operations. The built-in HTTP transport
implements all four. A custom transport must implement the directory methods to
support automatic publication, `claimAccount()`, and `rotate()`.
