# Transport implementation

Strict JSON codecs and the browser-safe Fetch transport. HTTP response bodies
are consumed incrementally under hard bounds; protected reads acquire and sign
one-use challenges automatically.

```text
RelayTransport.readEvents
    -> POST read-challenge
    -> sign(topic + cursor + limit + wait)
    -> POST protected read
    -> bounded stream decode -> retained event page
```

Publication follows the shorter exact-event path, while all JSON conversion
remains behind strict wire codecs.
