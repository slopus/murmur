# Storage tests

Runs the ordered-event, monotonic-head, and collapse contract against SQLite and
real in-process PGlite transactions. Direct page-selection tests instrument
candidate byte accounting so large-page complexity regressions are deterministic
instead of timing-dependent. Store instrumentation verifies that adversarial
maximum-size metadata pages hydrate only the selected event JSON rows. SQLite
overflow-row coverage also requires an explicit covering-index plan and a
generous repeated-read performance ceiling.
