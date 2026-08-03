# Transport implementation

Concrete transports such as HTTP long-polling live here. The public protocol
types and signing helpers remain at the module top level.

`httpTransport.ts` also holds the ephemeral path: `publishEphemeral` POSTs raw
octet-stream bytes, and `openStream` drives an `EventStreamParser` over the
`text/event-stream` body. The parser is byte-oriented so a chunk boundary may
fall inside a line or a UTF-8 sequence; it splits on the `\n` byte (which never
appears mid-sequence), strips a trailing `\r`, joins `data:` lines with `\n`, and
bounds both the pending line and the accumulated event at 256 KiB.
