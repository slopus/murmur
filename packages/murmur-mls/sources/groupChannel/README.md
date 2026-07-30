# Group channel

Transport adapter from an authenticated `MlsEpochState` to the
transport-agnostic `MurmurClient`.

The application owns the single client sync loop and dispatches received events
by topic. Opened and deferred events preserve manual acknowledgement. Deferred
events are not deleted automatically because they may belong to a future epoch.
