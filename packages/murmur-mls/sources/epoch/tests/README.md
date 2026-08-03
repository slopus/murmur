# Epoch tests

Coverage for Welcome-to-epoch handoff, bidirectional application messages,
local leaf ownership, secret destruction, transactional transitions, and an
integrated Remove-plus-Add flow across retained, removed, and joining members. It also covers the
RFC 9420 exporter: two members of one epoch derive identical material, a
different label or context derives unrelated material, and exporting neither
advances the ratchet nor changes the durable checkpoint.
