# Relay build scripts

`buildBinary.ts` compiles the standalone relay entry point into one
platform-specific executable with Bun. Its build plugin replaces the
`node:sqlite` module with a narrow `bun:sqlite` compatibility adapter only
inside that executable; the ordinary Node build is unchanged.

```text
sources/main.ts
      |
      +-- node:sqlite --[build adapter]--> bun:sqlite
      |
      `-- Bun runtime + bundled dependencies --> one executable
```

The executable embeds the Bun runtime, relay code, and JavaScript dependencies.
It still uses operating-system libraries and external persistence, so it is a
standalone executable rather than a fully statically linked binary.
