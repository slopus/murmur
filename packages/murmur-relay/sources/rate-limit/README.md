# Rate limiting

The HTTP layer consumes weighted tokens from both network-address and
authenticated-author buckets.

```text
request -> ip:<address> bucket
publish -> ip:<address> bucket + author:<signing-key> bucket
```

`RateLimiter` is replaceable. The default in-memory implementation bounds its
LRU map so rotating attacker-controlled keys cannot cause unbounded growth.
