# Identity implementation

Strict clean-rewrite codecs for the single public identity key, authenticated
friend requests/responses, profiles, durable lifecycle records, and exact
transport-neutral outbox items. Outgoing-request trackers strictly persist
both publication state and the signed causal predecessor needed to validate
late responses. There are no legacy two-key decoders or migration branches.
