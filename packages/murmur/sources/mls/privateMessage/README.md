# Private messages

The application-only RFC 9420 `PrivateMessage` profile. It signs
`FramedContentTBS`, encrypts application content with a Secret Tree generation
key, hides sender data with the epoch sender-data secret, applies reuse guards,
supports zero padding, and restores ratchet state after failed authentication.

Proposal and Commit content are intentionally not handled here.

```text
application bytes + sender credential
        -> sign framed content
        -> Secret Tree generation key
        -> encrypt content + hide sender
        -> MLS PrivateMessage
receiver -> reveal sender -> derive same generation -> verify/open
```

Failed authentication restores receiver ratchets so a malicious delivery cannot
consume the key needed by a later valid event.
