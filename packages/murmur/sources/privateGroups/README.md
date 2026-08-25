# Private-group identifiers and credentials

This internal domain composes the generic `math` module into the private-group
protocol from the master plan. It is not exported by the published package
entry point.

```text
group master secret
        |
        +--> opaque group id
        +--> deterministic UID ElGamal parameters
        +--> metadata keys
        `--> group proof parameters

authenticated account -- blind request --> credential issuer
        |                                     |
        `----------- unblinded MAC <----------'
                         |
encrypted UID -------- same-id presentation --------> keyed verifier
```

Presentations reveal only the credential expiry and group-specific encrypted
entry. A fresh randomizer hides the issuance transcript. The Fiat-Shamir
context includes the opaque group, encrypted entry, expiry, replay nonce, and
caller-supplied operation context.
