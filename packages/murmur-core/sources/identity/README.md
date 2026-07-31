# Identity

An identity combines independent Ed25519 signing and X25519 encryption keys.
Profiles are signed by their owner and sealed directly to the contact who may
read them.

First contact uses `identityInboxTopic(signingKey)`. This topic is intentionally
publicly derivable: anyone holding the identity token can read it. The sealed
payload contains the sender identity, and the relay event uses a one-use signing
identity. The public inbox therefore leaks that N unlinkable contact requests
exist, but not which identities sent them. It must carry no ongoing chat
traffic.

Optional private profile data, such as the CLI's MLS KeyPackage, is signed and
sealed in the same envelope rather than exposed beside it.

```text
first contact: public inbox -> sealed profile
ongoing chat:  X25519 shared secret -> pairwise capability topic
```

`pairwiseTopic(self, peer)` hashes an X25519 shared secret with a fixed domain
and both encryption public keys in canonical order. Alice and Bob derive the
same topic; public identity tokens alone do not reveal it.
