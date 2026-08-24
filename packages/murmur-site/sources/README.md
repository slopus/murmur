# sources

The deployed asset directory. Cloudflare serves the site files verbatim; there
is no build step. `.assetsignore` excludes this directory README from the public
manifest.

```text
request
   |
   v
Cloudflare static assets  <-- _headers and .assetsignore (configuration, never served)
   |
   +-- /            -> index.html --> /site.css --> /site.js
   +-- /<anything>  -> 404.html   --> /site.css
```

## index.html

The whole landing page, in document order:

```text
header .chrome        wordmark, section nav, version pill, appearance, GitHub
main #main
  #top                hero: claim, install strip, CTAs, topology diagram
  #scope              what Murmur is / is not
  #how-it-works       identity -> invitation -> session -> synchronization
  #contacts           invitations, the mutual contact handshake, revocation
  #cryptography       cipher suite 0x0001, RFC links, audit disclosure
  #relay              trust boundary: what the relay sees and never receives
  #durability         offline sends, persist-then-acknowledge, MurmurStore
  #services           typed services, four tabbed code samples
  #limits             the honest list
  #install            install command, local relay recipe, doc links
footer .site-footer   repository, package, licence, version line
```

Structure rules the tests enforce: one `<h1>`, unique ids, a skip link that
reaches `#main`, every `<section>` named by `aria-labelledby`, every in-page
anchor resolving, every off-site link carrying `rel="noreferrer"`, every
`<button>` declaring a type, and the tab set wired in both directions
(`aria-controls` out, `aria-labelledby` back).

The topology diagram is hand-authored inline SVG drawn in `currentColor` with a
`<title>` and `<desc>`, so it inverts with the appearance and reads to a screen
reader. It is not an image file, which is why the page loads no `<img>` at all.

## site.css

Colour and typography use Happy's desktop role names so a Murmur page and a
Happy window resolve the same values. Three token blocks define every colour:
`:root, .happy-theme-light`, the `prefers-color-scheme: dark` media query, and
`.happy-theme-dark` for the explicit override. A colour literal anywhere else is
a defect.

Layout is flexbox on a 4px grid with a 1120px content measure and a 68ch prose
measure. Sections are full-bleed and separated by 1px hairlines; nothing floats
on a shadow. One responsive breakpoint at 768px collapses the two-column
regions, drops the section nav, and reduces the display sizes.

## site.js

Loaded from `<head>` _without_ `defer` so the stored appearance lands on
`<html>` before first paint. It does three things and touches no network:
appearance toggle, code tabs with arrow-key support, and the install-command
copy button. `localStorage` failures are tolerated silently; a browser without
the clipboard API simply hides the copy button.

## \_headers

Static response headers. Cloudflare treats this as configuration and never
serves it. The content security policy is `default-src 'none'` with same-origin
script and style, which is only possible because the page has no inline script,
no inline style, and no third-party subresource.
