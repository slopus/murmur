# Releasing `@slopus/murmur`

`@slopus/murmur` is the only npm-published package. `@murmur/relay` is private.

Before changing the version:

```bash
pnpm format
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm --filter @slopus/murmur pack --pack-destination ../../.context
```

Inspect the tarball. It must contain only `dist`, `LICENSE`, `README.md`, and
`package.json`; the package exposes only the root entry and `package.json`.

Then update the version using pnpm, commit with an Angular-style message, and
publish from `packages/murmur-core`:

```bash
pnpm publish --access public
```

Never publish the relay package.
