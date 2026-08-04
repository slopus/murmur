# Group context

Exact extension-free RFC 9420 `GroupContext` encoding, transcript-hash updates,
and epoch confirmation tags. Callers supply the encoded
`ConfirmedTranscriptHashInput`; the proposal/commit layer owns that structure.

```text
GroupContext(E) + confirmed transcript input
                 -> confirmed_transcript_hash
                 -> confirmation_tag
                 -> interim_transcript_hash
                 -> GroupContext(E+1)
```

This domain binds the public tree, epoch number, and transcript history into
the key schedule without interpreting proposal semantics.
