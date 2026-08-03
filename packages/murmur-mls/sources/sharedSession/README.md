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

## The non-durable channel

`openEphemeralChannel()` adds a second surface over the _same_ MLS group, for
traffic that must not be written down. It is deliberately the opposite of a
post in every respect that matters:

|                      | `post()` / `sendControl()`    | ephemeral channel           |
| -------------------- | ----------------------------- | --------------------------- |
| durability           | committed to `MurmurStore`    | never stored                |
| ordering             | total, against the transcript | per sender only             |
| replay after restart | yes                           | no                          |
| loss                 | never                         | expected, bounded, reported |
| latency              | one durable sync              | one relay hop               |
| keying               | MLS application ratchet       | MLS exporter, same epoch    |

Because the frames are keyed from the current epoch of the existing group,
membership, the owner-only-committer rule, and epoch-based revocation apply
unchanged: there is no second group and no second trust root. A revoke Commit
rekeys the owner's channel immediately, so in-flight ephemeral traffic closes
without waiting for the next durable sync, and the revoked member's frames stop
opening at once.

`sendControl()` is the other half of the same problem. Capability negotiation
is low-volume and durable-appropriate, but it is not chat: it travels as its
own frame kind carrying opaque canonical JSON, exactly as an owner entry does,
so structured friend data never has to be encoded into conversational text and
filtered back out.
