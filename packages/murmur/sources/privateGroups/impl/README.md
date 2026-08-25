# Private-group implementation

- `parameters.ts` derives group and issuer parameters.
- `uid.ts` constructs deterministic group-scoped encrypted identifiers.
- `credentials.ts` implements blind issuance and client finalization.
- `presentation.ts` proves credential and encrypted UID share one identifier.
- `codec.ts` implements strict canonical wire encodings.

The issuer/verifier retains the algebraic-MAC key. Group members retain the
group master-derived UID and metadata secrets. The service receives only group
public parameters and opaque ciphertexts.
