# Discovery tests

Tests cover canonical round trips, identity and KeyPackage binding, tampering,
expiry, duplicate packages, and unknown-field rejection.

```text
valid bundle -> serialize -> parse -> equivalent public material
tamper / stale / duplicate / extra field -----------> reject
```
