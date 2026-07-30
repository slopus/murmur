# Epoch

Ownership wrapper for an already authenticated RFC 9420 epoch. It binds the
local signing key to a leaf, owns and destroys epoch secrets, maintains the
Secret Tree, and seals/opens application `PrivateMessage` values.

Ownership transfers only after successful construction: the state clones the
secrets and TreeKEM private path into private storage and zeros all
caller-provided secret arrays. Construction failure leaves cleanup with the
caller.

Integrated epochs own the authenticated public ratchet tree and credential
validator. Full Add/Remove transitions create or open the mandatory UpdatePath
and are staged with explicit `commit()`/`cancel()` ownership. Sealing pauses
while a transition is pending; commit destroys the old epoch, while cancel
destroys the staged state and resumes the old one. Welcome adoption derives and
validates the joining member's private direct path.

The earlier add-only/external-tree methods remain as a compatibility layer for
callers which have not moved tree ownership into this state.
