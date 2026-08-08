# Cipher-suite tests

HPKE base-mode agreement/tamper tests and MLS labeled KDF/signature domain
separation.

```text
sender setup == receiver setup -> identical context
wrong info/key/ciphertext ------> authentication failure
same bytes + different MLS label -> different derived output/signature
```

The suite tests isolate algorithm and label correctness before tree or epoch
state is involved.
