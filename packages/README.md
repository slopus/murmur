# Workspace packages

```text
packages/
    +-- murmur-core/          @slopus/murmur browser-safe stateful library
    +-- murmur-chat-service/  @murmur/chat-service private application layer
    `-- murmur-relay/         @murmur/relay ordered opaque-event service
```

MLS is compiled once as an internal part of `murmur-core`; it is not a separate
workspace package or package export.

The chat service remains a private workspace package. It builds application
message and encrypted-attachment semantics above opaque Murmur group events;
none of those semantics enter the published core or dumb relay.
