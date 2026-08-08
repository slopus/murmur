# Workspace packages

```text
packages/
    murmur/        @slopus/murmur         published browser-safe library
    murmur-relay/  @slopus/murmur-relay   private Node queue relay
```

The core package owns identity, signed discovery, durable delivery processing,
MLS, and the `MurmurClient` session façade. The relay owns only authenticated
pending identity queues and storage backends.
