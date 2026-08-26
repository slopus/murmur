# Account-secret implementation

`accountSecretKdf.ts` validates the generated-string format and passwords,
derives the generated and password components with HKDF-SHA-256 and scrypt,
and combines them with a second domain-separated HKDF.

`accountSecretCodec.ts` owns the canonical binary envelope and ordered
root-material payload. It validates lengths and fixed cost parameters before
running scrypt, authenticates the complete header as AEAD associated data, and
permits only strictly increasing payload field identifiers.
