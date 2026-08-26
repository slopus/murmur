# Durable fanout

Negotiated publication persists one ordered manifest containing the already
authorized direct or relay-derived recipient set before acceptance. Each
recipient insertion is idempotent and independently marked complete; an alarm
retries the oldest incomplete manifest until it finishes or expires.
