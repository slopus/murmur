# Identity implementation

Strict clean-rewrite codecs for the single public identity key, authenticated
friend requests/responses, profiles, durable lifecycle records, and exact
relay-addressed semantic outbox items. Outgoing-request trackers strictly persist
both publication state and the signed causal predecessor needed to validate
late responses. There are no legacy two-key decoders or migration branches.

```text
profile + causal request ----> signed/sealed request codec
response + request ID -------> signed/sealed response codec
lifecycle record <-----------> strict durable codec
semantic outbox + tracker ---> crash-safe retry inputs
```

The parent identity module owns state transitions; this directory normalizes
their exact wire and storage representations.
