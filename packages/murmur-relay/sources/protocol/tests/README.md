# Protocol tests

Exact wire round trips, strict field rejection, canonical recipient ordering,
owning-account binding, and Ed25519 tamper detection for delivery, queue-read,
and acknowledgement bodies.

```text
typed body -> JSON -> exact parse -> signature verification
tamper / unknown field / invalid point ---------> rejection
```
