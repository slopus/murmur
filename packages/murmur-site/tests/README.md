# tests

Deterministic assertions over the shipped files in `../sources`. They run on
`node:test` and `node:assert` with no dependency, no browser, no network, and no
build step:

```bash
pnpm --filter @slopus/murmur-site test
```

Because there is no compiler between `sources` and the deployed bytes, these
tests read the exact artefact Cloudflare serves. The files are parsed with
targeted regular expressions rather than a DOM library; that is a deliberate
trade of generality for having zero dependencies, and it works because the
markup is hand-written and stable.

## What is covered

```text
package layout        private package, no dependencies, README per directory,
                      source README excluded from the public asset manifest
worker configuration  assets-only, named "murmur", no bindings or server state
security headers      CSP directives, HSTS, nosniff, referrer, frame options
                      + proof the pages contain no inline script or style
no external assets    every subresource is a local path that exists on disk;
                      no @import, no @font-face, no url(), no fetch in script,
                      no analytics vendor anywhere
accessibility         lang, one <h1>, banner/nav/main/contentinfo, skip link,
                      unique ids, aria-labelledby resolution, live in-page
                      anchors, bidirectional tab wiring, button types, abbr
                      titles, rel=noreferrer on off-site links
visual system         no gradients, no colour literal outside a token block,
                      Happy role names, the 6/8/10/14 radius scale, teal links,
                      black primary action, 4px spacing grid, no keyframes, no
                      transition over 200ms, reduced-motion block, focus-visible
content               the protocol explanation, the four steps, the mutual
                      contact handshake, RFC and Noble reference links, the
                      exact primitives in use, the relay trust boundary, the
                      metadata caveat, offline durability, the service contract,
                      escaped code samples, install and repository links
honest claims         the audit disclosure and the limits list are present; a
                      denylist of absolute security claims is absent; primitives
                      the library does not implement are never named
```

## Adding a claim to the page

A new claim about the protocol belongs in `content:` — assert the exact phrase,
so deleting or softening a disclosure fails the suite. A new cryptographic
reference belongs in the `references` map in `content: cryptography references`,
which asserts the literal `href`. If a claim cannot be traced to `docs/`, it
does not belong on the page.
