# Private messages

The application-only RFC 9420 `PrivateMessage` profile. It signs
`FramedContentTBS`, encrypts application content with a Secret Tree generation
key, hides sender data with the epoch sender-data secret, applies reuse guards,
supports zero padding, and restores ratchet state after failed authentication.

Proposal and Commit content are intentionally not handled here.
