# Relay sources

```text
protocol -> relay policy -> atomic queue storage
                   \-----> Fetch and Node hosts
```

The relay stores one encrypted delivery record plus one queue reference per
recipient until acknowledgement or expiration. It has no topic or application
semantics.
