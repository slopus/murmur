# Ephemeral frame implementation

`frameHeaderCodec.ts` encodes and decodes the fixed 36-byte cleartext header
that precedes every ephemeral frame. It is a pure codec: it validates field
ranges and returns `undefined` for anything that is not a version 1 header,
leaving every authentication decision to the cipher one level above.
