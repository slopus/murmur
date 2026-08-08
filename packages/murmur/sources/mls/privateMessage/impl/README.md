# Private message internals

Strict codecs for the application-only RFC 9420 `MLSMessage`,
`PrivateMessage`, sender data, private content, and their authenticated-data
structures.

```text
MLSMessage(private)
  +-- group/epoch/content type
  +-- encrypted sender data
  +-- authenticated data
  `-- encrypted content + reuse guard
```

The codec exposes exact components to the parent module, which owns signatures,
padding, and Secret Tree generation keys.
