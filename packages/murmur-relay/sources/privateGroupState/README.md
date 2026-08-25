# Private-group state service

This module stores one canonical encrypted record per opaque group identifier.
It sees only group capabilities, deterministic encrypted member entries, fixed
roles, revisions, sizes, and access timing.

```text
authenticated account -> blind credential issuance authority
                                      |
opaque entry -> randomized proof -> short-lived scoped token
                                      |
                               SQLite canonical record
```

The service receives cryptographic issuance and presentation verification as a
narrow authority. It never receives a group master secret or plaintext account
roster. Production HTTP integration must supply the authenticated account
identifier from the authenticated session, never from an unauthenticated
request field.

Tokens contain no account identifier and are scoped to one opaque group,
encrypted entry, fixed role, and expiry. SQLite stores only the current record,
so storage remains bounded by explicit group, member, record-byte, and pending
challenge limits.

This feature requires external cryptographic review before production use. It
hides the persistent social graph from this service, not IP, timing, volume,
cardinality, role, or record-size metadata.
