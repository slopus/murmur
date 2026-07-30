# MLS Commit

Authenticated RFC 9420 membership transitions. The full profile accepts inline
Add and Remove proposals, applies Remove before ordered Add operations, creates
a mandatory UpdatePath, advances the transcript with its commit secret, and
produces a Welcome when new members are present.

The earlier partial Add-only API remains available for compatibility and keeps
its external-tree transaction contract. The full profile owns candidate public
tree construction and returns the retained member's next private TreeKEM keys:

```text
Remove -> Add -> UpdatePath -> authenticated Commit
                         |-> retained members derive commit secret
                         +-> added members receive Welcome
```
