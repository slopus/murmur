# Commit tests

Full Add/Remove Commit wire round trips, UpdatePath/key-schedule agreement,
Welcome join, removed-member exclusion, tamper rejection, and tree validation.

```text
old epoch -> Remove(B) + Add(D) Commit -> next epoch
   |                |                       |
 retained A/C    Welcome(D)             B excluded
   `-------------- key/transcript agreement --------'
```

One integrated vector proves the codec, TreeKEM path, Welcome, and next key
schedule agree on the same transition.
