# Key-package tests

Binary round-trip, nested signatures, lifetime, tamper rejection, independent
HPKE keys, and secret destruction.

```text
create bundle -> encode/decode -> signature + key binding
      |              |                    |
 lifetime edges   corrupt bytes        reject mismatch
      `-----------------------------> destroy secrets
```

The suite proves both the public advertisement and its private durable bundle
refer to the same one-use keys.
