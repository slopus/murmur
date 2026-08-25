# Accounts and devices

This module defines the stable account-signing identity and its independently
keyed device roster. The account key signs roster state only. Device keys sign
delivery, MLS, and provisioning traffic and own independent inboxes and
ratchets.

```text
account signing key
        |
        +-- signed roster revision
                |
                +-- active device A -> inbox + MLS leaves
                +-- active device B -> inbox + MLS leaves
                `-- revoked device C
```

Roster revisions name their parent hash. Authenticated siblings are ordered by
their exact SHA-256 digest, so every participant presented with the same forks
selects the same winner without relay discretion. Provisioning follows the
Signal linking shape: a new device presents a short-lived URI containing an
ephemeral key and device proof, and an active device returns an encrypted,
transcript-bound account authorization.
