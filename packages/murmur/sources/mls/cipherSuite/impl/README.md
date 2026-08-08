# Cipher-suite implementation

RFC 9180 labeled KEM/KDF setup and one-shot base-mode contexts. No application
or group state lives here.

```text
X25519 DH -> labeledExtract/labeledExpand -> key + nonce
                                            |
plaintext + context --------------------> AES-128-GCM
```

These one-shot contexts are consumed by Welcome and UpdatePath HPKE, never by
the application-message Secret Tree.
