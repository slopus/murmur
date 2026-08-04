# Chat service tests

End-to-end tests run real Murmur peers against an in-process SQLite relay.

```text
Alice Chat --\
Bob Chat   ---- real Murmur MLS ---- in-process relay
Carol Chat --/
```
