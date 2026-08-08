# MLS KeyPackage

Murmur's RFC 9420 KeyPackage profile binds:

- an X25519 init key;
- an X25519 leaf encryption key;
- the Ed25519 Murmur identity in BasicCredential and signature key;
- a finite `notBefore`/`notAfter` lifetime;
- signatures over the LeafNode and KeyPackage.

`createMlsKeyPackage` returns public material plus one-use private HPKE keys.
The private bundle is serialized only into the client store and is destroyed
after successful Welcome processing or expiry. Discovery exposes the public
KeyPackage and signs the outer bundle with the same Murmur identity.

```text
public KeyPackage ---- shared in discovery
private HPKE keys ---- durable local state ---- consumed by Welcome
```

KeyPackage references use the RFC label and are the stable one-use claim key.
