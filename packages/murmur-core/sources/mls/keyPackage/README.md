# Key packages

The supported RFC 9420 KeyPackage profile uses:

- protocol version `mls10`;
- cipher suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`;
- BasicCredential containing the Murmur Ed25519 identity key;
- empty extensions;
- capabilities for Add, Update, and Remove proposals;
- independent one-use init and leaf HPKE keys.

KeyPackage and LeafNode signatures use their RFC labels. Consuming a bundle
zeros both HPKE secret keys.

Applications can serialize a bundle into private durable state. Restoration
revalidates the public KeyPackage and proves that both stored HPKE private keys
own the exact public init/leaf keys before returning the one-use bundle.

```text
identity signing key
      |
      v
KeyPackage + init private key + leaf private key
      |             |
 public announce    `-> private durable bundle
      |
 reserve once -> Add Commit -> Welcome open -> consume + zero
```

The facade maintains separate per-friend public and private pools around this
one-use cryptographic object.
