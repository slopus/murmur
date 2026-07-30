# Epoch

Ownership wrapper for an already authenticated RFC 9420 epoch. It binds the
local signing key to a leaf, owns and destroys epoch secrets, maintains the
Secret Tree, and seals/opens application `PrivateMessage` values.

Ownership transfers only after successful construction: the state clones the
secrets into private storage and zeros all caller-provided secret arrays.
Construction failure leaves cleanup with the caller.

Add-only transitions are staged here with explicit `commit()`/`cancel()`
ownership. Sealing pauses while a transition is pending; commit adopts the
validated external tree and destroys the old epoch, while cancel destroys the
staged epoch and resumes the old one. TreeKEM validation and tree storage remain
external, and Remove/Update transitions remain unavailable until UpdatePath is
implemented.
