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
