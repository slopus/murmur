# Epoch implementation

Internal codecs for durable local MLS epoch state. Persisted state contains
epoch and ratchet secrets, so callers must store the encoded bytes with the
same confidentiality and filesystem protections as identity private keys.
