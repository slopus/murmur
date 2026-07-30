# Sources

Public exports start in `index.ts`. Each directory owns one domain; secondary
encoding and cryptographic mechanics live below that domain in `impl`.

```text
index.ts
  |-- client
  |-- crypto
  |-- identity
  |-- storage
  `-- transport
```
