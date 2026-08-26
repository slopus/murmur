# Accounts

The account domain tracks multiple device identities under one restored account
signing root. It owns relay-roster codecs, convergence jobs, and lifecycle
records.

## Registration

A store opened from an account identity generates its own device key and
self-registers it with an account-signed mutation carrying a fresh MLS
KeyPackage. No existing device approval or account-root transfer occurs. Any
restored device can likewise remove itself or another current device.

## Roster convergence

The relay owns one current monotonic roster revision per exact account identity.
Registration carries a monotonic reset generation; removal names the current
generation. Ordinary mutation notifications and stale-publication responses
feed durable convergence jobs for matching MLS additions and removals.

Public session views expose account identities even when several device leaves
participate internally. Dormancy reporting identifies active sibling devices
without authenticated activity for six months; revocation remains explicit.
