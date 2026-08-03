# Shared-session implementation

This directory contains strict canonical codecs and mechanical durable-record
helpers. Public owner/member state machines stay one level above so their
prepare, persistence, publication, and callback ordering is visible.

All owner frames use an inner Ed25519 signature in addition to MLS
authentication. The signature preimage has a fixed shared-session domain and
binds the opaque share ID, raw MLS group ID, complete frame, and owner key.
