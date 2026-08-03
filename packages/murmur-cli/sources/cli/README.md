# Command-line interface

The CLI parser is deliberately dependency-free and non-interactive. Commands
emit JSON so agents and people can consume the same stable output.

Current identity, private-message, and group commands:

```text
sign-in, me, contacts add/remove, send, sync, messages, attachment,
groups create/invite/remove/send/messages, documents create/insert/delete
```

Relay and database selection are bootstrap options handled before command
execution. The CLI uses the exported public Murmur relay by default; repeatable
`--relay` arguments override `MURMUR_RELAYS`, which overrides that default.
