# MLS Commit

Authenticated RFC 9420 membership transitions. Commits accept inline Add and
Remove proposals, apply Remove before ordered Add operations, create a mandatory
UpdatePath, advance the transcript with its commit secret, and produce a Welcome
when new members are present. The implementation owns candidate public-tree
construction and returns the retained member's next private TreeKEM keys:

```text
Remove -> Add -> UpdatePath -> authenticated Commit
                         |-> retained members derive commit secret
                         +-> added members receive Welcome
```
