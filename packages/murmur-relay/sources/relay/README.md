# Relay policy

`RelayService` validates signed writes, enforces typed topic capabilities,
issues one-use read challenges, bounds resources, and coordinates long polling.

Long polling registers a waiter and then rechecks storage, closing the
read-before-park race. Cross-process wake sources reduce latency; timeout-backed
reads preserve correctness if a notification is lost.

```text
publish: validate -> authorize writer -> store exact event -> notify topic
read:    challenge/proof -> authorize reader -> page from cursor
long poll: register waiter -> recheck store -> wait/timeout -> re-read
```

`RelayService` coordinates policy and ordering without inspecting any encrypted
friend or MLS payload.
