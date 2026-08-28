# Sources

`index.ts` is the complete public surface. It exposes the NaCl-like stateless
operations and the small result contracts from `types.ts`.

```text
caller-owned secret state bytes
          |
          v
 create / update / apply / join
          |
          v
replacement secret state bytes + fresh secret key
```

Cryptographic machinery, tree mutation, and defensive codecs are private to
`impl`.
