# Identity

This directory reserves the identity-domain boundary. Device identity roots and
public-key operations currently live in `sources/crypto`; account-device roster
state lives in `sources/accounts`.

The future exact-key identity directory will be implemented here without
changing queue or MLS ownership boundaries.
