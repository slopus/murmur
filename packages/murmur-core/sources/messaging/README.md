# Messaging

Private application content can be carried inside an encrypted MLS application
message or sent directly to an identity inbox. The direct envelope uses an
ephemeral X25519 sealed box plus an Ed25519 signature bound to the recipient;
it provides authenticated end-to-end encryption, while ongoing group-shaped
conversation state uses MLS for forward secrecy and post-compromise security.
Direct-message recipients must call `acceptPrivateMessageFromContact()` with
durable storage and an application-persistence callback before acknowledging a
relay delivery. The callback and authenticated sender/message-ID marker commit
in one transaction, so a reported duplicate is safe to acknowledge without a
message-loss crash window. Same-ID content collisions are rejected.

Files are always encrypted before upload. The descriptor contains the secret
file key and therefore must only appear inside encrypted application data.

```text
plaintext file -> AES-256-GCM -> relay blob
       key + metadata --------> encrypted message descriptor
```
