# Identity

An identity combines independent Ed25519 signing and X25519 encryption keys.
Profiles are signed by their owner and sealed directly to the contact who may
read them. Relays route the opaque envelope by the recipient's public identity.

```text
profile -> owner signature -> X25519 sealed box -> recipient inbox topic
```
