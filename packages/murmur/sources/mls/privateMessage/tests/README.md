# Private message tests

Coverage for application-message encryption, hidden sender data, signatures,
padding, tamper rejection, and transactional generation handling.

```text
seal(A,generation n) -> open(B) -> authenticated application bytes
tamper sender/content/tag -----> reject + restore generation n
padding/reuse guard -----------> hidden but round-trippable framing
```

The rollback assertion is the critical durability link between cryptographic
failure and later valid delivery.
