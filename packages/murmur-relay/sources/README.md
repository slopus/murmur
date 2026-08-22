# Relay sources

```text
invitation bytes -> digest/TTL policy -> bounded opaque cache
queue protocol --> relay policy ------> atomic queue storage
                          \-----------> page JSON / ordered SSE
                                        Fetch and Node hosts
```

The relay stores one encrypted delivery record plus one queue reference per
recipient until acknowledgement or expiration. It also stores public signed
invitation bytes for at most five minutes under their SHA-256 digest. It has no
topic, directory, or application semantics.

The additive `session` boundary issues device-bound temporary routing
capabilities after application authorization. The `websocket` boundary maps
those capabilities onto the same signed queue operations; HTTP/SSE stays
available unchanged.
