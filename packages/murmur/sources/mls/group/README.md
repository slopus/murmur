# Group creation

RFC 9420 Section 11 one-member group initialization for Murmur's cipher suite
and BasicCredential profile.

The creator samples a random group ID and epoch secret, installs its signed
KeyPackage leaf as the one-node ratchet tree, uses the required empty epoch-zero
confirmed transcript hash, and derives the initial interim transcript hash from
the confirmation tag. Further members join through ordinary full Add Commits
and Welcome messages.

```text
creator KeyPackage + random group ID + epoch secret
                         |
                         v
             one-leaf group at epoch 0
                         |
                  ordinary Add Commit
                         v
                multi-member epoch 1
```

There is no separate two-person construction path; every larger group grows
from the same one-member primitive.

Bootstrap confirmation metadata is carried by the retained initial Commit.
