# Epoch

Ownership wrapper for an already authenticated RFC 9420 epoch. It binds the
local signing key to a leaf, owns and destroys epoch secrets, maintains the
Secret Tree, and seals/opens application `PrivateMessage` values.

Ownership transfers only after successful construction: the state clones the
secrets into private storage and zeros all caller-provided secret arrays.
Construction failure leaves cleanup with the caller.

Epoch transition is deliberately outside this module: the Commit/TreeKEM layer
must first validate the next public tree, context, transcript, confirmation,
and key schedule.
