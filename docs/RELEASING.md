# Releasing Murmur

One version tag releases the browser-safe client library and the relay
container, then creates a GitHub Release.

```text
packages/murmur-core/package.json version X.Y.Z
                    |
                    v
               tag vX.Y.Z
                    |
        +-----------+------------+
        |                        |
        v                        v
@slopus/murmur on npm   ghcr.io/slopus/murmur-relay
        |                        |
        +-----------+------------+
                    |
                    v
             GitHub Release
```

## One-time repository setup

Configure npm Trusted Publishing for `@slopus/murmur` with these values:

| Field        | Value         |
| ------------ | ------------- |
| Organization | `slopus`      |
| Repository   | `murmur`      |
| Workflow     | `publish.yml` |
| Environment  | `npm`         |

The publication job runs in the GitHub environment named `npm` and exchanges
GitHub's short-lived OIDC identity for npm publication access. It does not use
an npm token. GitHub's built-in `GITHUB_TOKEN` publishes the container to GHCR
and creates the GitHub Release.

The first GHCR package may require changing its visibility to public in the
organization's package settings. The workflow publishes
`ghcr.io/slopus/murmur-relay`.

## Release procedure

1. Update `packages/murmur-core/package.json` to the intended version and commit
   the change.
2. Confirm local tests, typechecks, lint, formatting, and the package prepack
   checks pass.
3. Create and push the matching tag:

    ```bash
    git tag v0.2.0
    git push origin v0.2.0
    ```

The workflow rejects a tag that does not exactly match the package version.
Before publishing, it imports every package export in Node, bundles every
export for browsers, runs the repository checks, and inspects the npm tarball.

Successful releases publish these immutable/versioned artifacts:

- `@slopus/murmur@X.Y.Z`
- `ghcr.io/slopus/murmur-relay:X.Y.Z`
- `ghcr.io/slopus/murmur-relay:X.Y`
- `ghcr.io/slopus/murmur-relay:latest`

The npm publication includes provenance. The container is published for Linux
amd64 and arm64 with an SBOM and BuildKit provenance. A prerelease version such
as `X.Y.Z-beta.1` publishes to npm's `next` tag and its exact container version;
it does not update the stable `X.Y` or `latest` container tags. GitHub marks the
corresponding release as a prerelease.
