# Commit encoding internals

Strict codecs for RFC 9420 PublicMessage Commits with ordered inline Add/Remove
proposals and a mandatory UpdatePath.

```text
PublicMessage
    `-- Commit
          +-- ordered Add/Remove proposals
          +-- mandatory UpdatePath
          `-- confirmation tag + membership tag
```

The codec preserves proposal order because the ratchet-tree transition and
transcript hash authenticate that exact sequence.
