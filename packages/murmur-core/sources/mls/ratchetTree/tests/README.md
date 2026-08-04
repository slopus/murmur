# Ratchet-tree tests

Coverage for resolution, filtered paths, add/remove/truncate behavior,
UpdatePath merging, key uniqueness, and RFC tree hashes.

```text
add leaf -> expand tree -> merge UpdatePath -> verify parent/tree hashes
remove leaf -> blank path -> filtered resolution -> truncate right edge
malformed keys/path/hash --------------------------> reject
```

The tests cover both logical tree operations and the public-node authentication
used by Commits.
