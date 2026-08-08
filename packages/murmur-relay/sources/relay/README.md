# Relay service

Validates signed deliveries and signed queue operations, enforces TTL and quota
policy, delegates atomic multicast and trimming to storage, and orchestrates
bounded long polling.

Every publication call must supply an explicit admission principal. The service
hashes it before storage and never falls back to the free protocol sender
identity. The HTTP boundary supplies the trusted socket/header principal or an
explicit shared embedding principal.

```text
signed request -> shape/time/signature policy -> atomic store operation
                                                  |
empty read -> bounded waiter -> wake hint --------+-> authoritative reread
```

Long polls are bounded globally and per recipient identity. Disconnects, relay
shutdown, and timeouts settle each waiter exactly once. A wake is only a latency
hint: duplicate publication also wakes readers, and every wake is followed by a
fresh store read.

UUIDv7 order is guaranteed only within one inbox and is not a cryptographic
guarantee. A malicious relay can suppress or equivocate about delivery order.
Clients must treat this as part of the untrusted-transport threat model rather
than assuming event IDs prove consensus.
