# MLS Commit

Authenticated RFC 9420 add-only membership transitions. Commits contain inline
Add proposals and no UpdatePath, advance the transcript and key schedule, and
produce a Welcome for the new members.

The ratchet tree is external in this layer. Creation and opening both require a
validator which checks leaf placement, every LeafNode, leaf and parent
encryption-key uniqueness, parent hashes, and the resulting tree hash:

```text
Add proposals -> caller applies RFC tree -> tree hash
             -> Commit authentication -> next epoch + Welcome
```

Remove and Update require TreeKEM UpdatePath support and are deliberately not
accepted by this profile yet.
