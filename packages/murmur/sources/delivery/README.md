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
