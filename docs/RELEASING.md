# Releasing `@slopus/murmur`

`@slopus/murmur` is the only npm-published package.
`@slopus/murmur-relay` is private and unpublishable.

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
The package's `prepack` lifecycle copies the repository-root `README.md` into
the package so npm and GitHub present the same integration guide.

Then update `packages/murmur/package.json`, commit with an Angular-style
message, push `main`, and create the exact matching version tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag triggers `.github/workflows/publish.yml`. GitHub's npm environment uses
trusted publishing with OIDC and provenance; no local npm token is involved.
The workflow repeats every gate, validates and installs the packed library,
publishes `@slopus/murmur`, builds the matching private relay container for
GHCR, and creates the GitHub Release.

Never run a local registry publish and never publish the relay package to npm.
