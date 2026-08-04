# Relay protocol

Strict codecs and canonical Ed25519 authentication for typed topic descriptors,
durable events, and protected-read challenges. Topic IDs are SHA-256 hashes of
canonical `(type, name, authorization key(s))` descriptors.
