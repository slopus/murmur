# Epoch

Ownership wrapper for an already authenticated RFC 9420 epoch. It binds the
local signing key to a leaf, owns and destroys epoch secrets, maintains the
Secret Tree, and seals/opens application `PrivateMessage` values.

Ownership transfers only after successful construction: the state clones the
secrets and TreeKEM private path into private storage and zeros all
caller-provided secret arrays. Construction failure leaves cleanup with the
caller.

Integrated epochs own the authenticated public ratchet tree and credential
validator. Full Add/Remove transitions create or open the mandatory UpdatePath
and are staged with explicit `commit()`/`cancel()` ownership. Sealing pauses
while a transition is pending; commit destroys the old epoch, while cancel
destroys the staged state and resumes the old one. Welcome adoption derives and
validates the joining member's private direct path.

`serialize()` snapshots the remaining Secret Tree frontier, sender ratchets,
skipped generations, TreeKEM path keys, and epoch secrets for durable local
storage. It deliberately excludes the identity signing secret. `deserialize()`
requires that secret again and proves that it owns the authenticated local
LeafNode before accepting the restored state. Persisted bytes are sensitive and
must receive identity-key-equivalent storage protection.

The key-schedule ancestors (`joiner_secret`, `member_secret`, `epoch_secret`,
and the original `encryption_secret`) are erased as soon as the Secret Tree is
initialized and are never serialized. Every successful application seal/open
and every adopted epoch transition advances `persistenceGeneration`. Durable
applications must atomically store the serialized epoch, that generation, and
the corresponding outbound event or accepted application record before
publishing or acknowledging. On restore, pass the independently retained
minimum generation to reject stale checkpoints. Whole-storage rollback requires
an external rollback-resistant counter; no local serialization format can
detect an attacker reverting both the checkpoint and its metadata.

`rebasePersistenceGeneration()` may only raise that local counter. It leaves
the authenticated MLS context, transcript, TreeKEM state, epoch secrets, and
Secret Tree frontier unchanged. The stateful facade uses it when
current-epoch applications arrive after a next epoch was staged but before its
Commit echo.

Durable inbound processing uses `openWithCheckpoint()`. It rolls the Secret Tree
and generation back if authentication or checkpoint serialization fails, so a
valid delivery is never hidden after its one-time key was consumed.

For an outbound Commit, persist the Commit bytes plus
`transition.serialize()` and `transition.persistenceGeneration` in the same
transaction before publication. Adopt the already-checkpointed transition only
when that exact Commit wins relay order; a publication result never adopts it.
The facade stages from a clone, so the live current epoch can still process
earlier relay-ordered applications. Echo adoption rebases the staged
checkpoint's local generation above those application mutations.

```text
active epoch E
   +-- seal/open application -> ratchet -> checkpoint E'
   `-- prepare Commit -------> staged E+1
                                  +-- cancel -> destroy E+1, resume E
                                  `-- commit -> destroy E, activate E+1
```

The wrapper is the single ownership boundary tying cryptographic mutation to
the facade's prepare-persist-publish/adopt durability rules.
