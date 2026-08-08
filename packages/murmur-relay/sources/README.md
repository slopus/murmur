# Relay sources

```text
invitation bytes -> digest/TTL policy -> bounded opaque cache
queue protocol --> relay policy ------> atomic queue storage
                          \-----------> Fetch and Node hosts
```

The relay stores one encrypted delivery record plus one queue reference per
recipient until acknowledgement or expiration. It also stores public signed
invitation bytes for at most five minutes under their SHA-256 digest. It has no
topic, directory, or application semantics.
