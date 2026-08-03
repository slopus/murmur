# Shared agent sessions

`sharedSession` is the browser-safe transport/control layer for sharing one
Rig-owned agent transcript with friends over an MLS group. Murmur treats every
transcript payload as opaque canonical JSON. It authenticates the owner,
membership grants, ordering, history pages, and friend posts without learning
or rewriting Rig's transcript schema.

```text
Rig transcript source
        |
        | bounded canonical-JSON pages
        v
owner -> encrypted blob history --+
  |                                |
  +-> signed owner frames -> MLS group -> member replica callbacks
  ^                                |
  +--------- friend text posts <---+
```

The owner is the only accepted MLS committer and the only authority for state,
entries, history offers, revocation, and terminal stop. Friend posts are
authenticated application frames but never carry state authority.

History is encrypted independently from MLS epochs. New and re-added members
receive chained offers containing at most 256 page descriptors apiece, while
each page is at most 4 MiB and 256 entries. A member persists one page at a
time, tracks the highest contiguous sequence, and buffers a bounded live tail.

Revocation prevents access to later epochs and later page keys. It cannot erase
plaintext or keys a member already saved. Applications must implement the
transactional `terminate` callback to cooperatively delete replica rows when an
authenticated end or MLS removal is received.
