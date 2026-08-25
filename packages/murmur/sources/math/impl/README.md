# Mathematics implementation

These files implement the mechanical parts of the internal mathematics module:

```text
codec.ts --------> transcript.ts
   |                    |
   +--> scalar.ts ------+--> schnorr.ts
   +--> point.ts -------+--> elgamal.ts
                        `--> algebraicMac.ts
```

Only public Noble Ristretto255 and hash APIs are used. No Edwards coordinates or
other Noble implementation fields are accessed.
