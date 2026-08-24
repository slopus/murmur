# @slopus/murmur-site

The Murmur landing page. One static HTML document, one stylesheet, one small
script, and a Cloudflare Worker that does nothing but serve them.

This package is private. It is never published to npm and it holds no product
code — `@slopus/murmur` remains the only published library in this workspace.

```text
packages/murmur-site/
├── package.json                 private, no dependencies
├── wrangler.production.jsonc    assets-only Worker named "murmur"
├── sources/                     the deployed asset directory, served verbatim
│   ├── index.html               the whole landing page
│   ├── 404.html                 not-found page, same shell
│   ├── site.css                 Happy's desktop roles, light and dark
│   ├── site.js                  appearance, tabs, copy — nothing else
│   ├── .assetsignore            excludes source docs from deployment
│   └── _headers                 static response headers (CSP, HSTS, ...)
└── tests/                       node:test assertions over those files
```

## Why there is no build step

The page has no framework, no bundler, no dependency, and no external asset. The
files in `sources` are exactly the files a browser receives. That keeps the
content security policy strict enough to deny every fetch directive by default,
makes the deployed bytes reviewable by reading them, and means the tests can
assert on the shipped artefact rather than on an input to a compiler.

It also means `sources` deviates from
[`master-plans/02-code-organization.md`](../../master-plans/02-code-organization.md):
there is no `index.ts` or `main.ts`, because there is no program. `sources` is
the asset root that `wrangler.production.jsonc` points at.

## Design

The page borrows Happy's desktop visual language so Murmur reads as part of the
same family: neutral surfaces meeting on hairlines, no shadows, no gradients,
black primary actions, Happy teal (`#2baccc`) for links and the focus ring, a
4px grid, and radii of 6 / 8 / 10 / 14. Colour tokens keep Happy's own role
names (`--text`, `--surface`, `--divider`, `--groupped-background`) rather than
introducing aliases, and a colour literal outside the token block is a defect
the tests catch.

Typography uses a Figtree-compatible system stack. Happy's bundled `Figtree`
variable font is not shipped here — a self-hosted font would be another
subresource to audit for no legible gain — so the stack names `Figtree` first
and falls through to the platform UI face.

Motion is restrained to state feedback: 120–160 ms colour and tab transitions,
nothing on arrival, no keyframes, and a `prefers-reduced-motion` escape.

## Content rules

Every claim on the page must be defensible against `docs/PROTOCOL.md`,
`docs/SECURITY.md`, and `docs/ARCHITECTURE.md`. In particular:

- the relay's metadata visibility is stated plainly, never softened;
- the missing independent security audit is stated on the page, not buried;
- the cryptography section names the primitives the code actually uses — MLS
  cipher suite `0x0001`, DHKEM(X25519, HKDF-SHA-256), AES-128-GCM, Ed25519 —
  and nothing else;
- there is no signup, pricing, or hosted relay, because none exists.

The test suite enforces the presence of those disclosures and the absence of
absolute security claims.

## Commands

```bash
pnpm --filter @slopus/murmur-site test                          # node --test
pnpm --filter @slopus/murmur-site cloudflare:dev:production     # local preview
pnpm --filter @slopus/murmur-site cloudflare:deploy:production  # deploy
```

`wrangler` is not a dependency of this package; the Cloudflare scripts expect it
on the path, the same way the relay package's deploy scripts do.

## Deployment

`wrangler.production.jsonc` declares an assets-only Worker: no `main`, no
bindings, no Durable Objects, no environment variables, no server state. The
Worker name is `murmur`, so the expected preview URL is
`https://murmur.<account>.workers.dev`.

Cloudflare consumes `sources/_headers` and `sources/.assetsignore` as
configuration and never serves either one. The ignore file keeps source
documentation out of the public manifest. The headers apply a content security
policy that permits same-origin script and style and denies everything else,
plus HSTS, `nosniff`, `no-referrer`, `X-Frame-Options`, and a
`Permissions-Policy` that turns off every device capability.
