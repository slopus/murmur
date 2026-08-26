# Relay storage

The storage seam provides atomic multicast, ordered bounded inbox reads, signed
prefix acknowledgement, expiry pruning, continuity generation, sender and
ingress-principal quota accounting, and restore declaration.

SQLite and PostgreSQL implement the same queue model:

```text
delivery row -> exact recipient references -> per-inbox sequence
sender/principal counters -> transactional quota enforcement
acknowledgement or expiry -> reference removal -> counter reclamation
```

Initialization accepts only the current exact schema. Unexpected or incomplete
tables and metadata fail closed.
