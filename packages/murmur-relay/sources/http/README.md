# HTTP

Fetch-compatible routes for signed publication, challenge issuance, protected
or public reads, long polling, and health. JSON bodies and response pages are
bounded. No secret capability material is accepted.

```text
HTTP request
  +-- POST /events ----------> decode -> RelayService.publish
  +-- POST /read-challenges -> issue one-use challenge
  +-- POST /events/read -----> verify proof -> ordered page/long poll
  `-- GET /health -----------> service status
```

This directory is the runtime-neutral Fetch boundary; sockets and databases
remain behind the server and relay-service interfaces.
