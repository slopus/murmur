# Utilities

Strict, self-contained byte and JSON codecs plus the monotonic UUIDv7 allocator
shared by the protocol and stores live here. Boundary helpers reject ambiguous
encodings so higher layers only handle normalized values.

The standalone runtime also uses the Pino-backed logger in this directory. It
renders only time, fixed-width module, and a self-contained message; interactive
terminals color modules deterministically while redirected and container output
remains plain text.

```text
untrusted bytes/JSON -> strict utility codecs -> normalized values
wall clock + last UUIDv7 -> monotonic UUIDv7 event ID

runtime event -> safe summary -> time | module | message
                               -> color only when interactive
```

Utilities deliberately avoid protocol state and redact errors into
credential-safe log summaries.
