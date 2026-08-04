# Workspace packages

```text
packages/
    +-- murmur-core/   @slopus/murmur browser-safe stateful library
    `-- murmur-relay/  @murmur/relay ordered opaque-event service
```

MLS is compiled once as an internal part of `murmur-core`; it is not a separate
workspace package or package export.
