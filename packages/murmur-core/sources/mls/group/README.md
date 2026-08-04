# Group creation

RFC 9420 Section 11 one-member group initialization for Murmur's cipher suite
and BasicCredential profile.

The creator samples a random group ID and epoch secret, installs its signed
KeyPackage leaf as the one-node ratchet tree, uses the required empty epoch-zero
confirmed transcript hash, and derives the initial interim transcript hash from
the confirmation tag. Further members join through ordinary full Add Commits
and Welcome messages.
