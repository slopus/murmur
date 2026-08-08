# Epoch key schedule

RFC 9420 joiner, member, and epoch secret derivation for cipher suite `0x0001`.
Every returned secret is an independent mutable array so callers can zero it
when advancing the epoch.

Epoch zero follows RFC 9420 Section 11 directly: the creator samples the
`epoch_secret`, derives the epoch outputs from it, and has no joiner/member
secret yet.

```text
Commit secret + prior init secret
              -> joiner_secret
PSK-free input -> member_secret
              -> epoch_secret
                   +-- confirmation/membership keys
                   +-- sender-data secret
                   +-- encryption secret -> Secret Tree
                   `-- exporter/resumption/init secrets
```

Each transition returns independently owned byte arrays so the epoch wrapper
can erase ancestors as soon as their descendants exist.
