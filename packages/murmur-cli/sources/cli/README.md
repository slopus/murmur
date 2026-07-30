# Command-line interface

The CLI parser is deliberately dependency-free and non-interactive. Commands
emit JSON so agents and people can consume the same stable output.

Current identity/private-message commands:

```text
sign-in, me, contacts add/remove, send, sync, messages, attachment
```

Relay and database selection are bootstrap options handled by `main.ts`.
