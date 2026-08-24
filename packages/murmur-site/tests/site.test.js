import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const sourcesRoot = join(packageRoot, "sources");

const read = (relativePath) => readFileSync(join(packageRoot, relativePath), "utf8");

const index = read("sources/index.html");
const notFound = read("sources/404.html");
const css = read("sources/site.css");
const script = read("sources/site.js");
const headers = read("sources/_headers");
const manifest = JSON.parse(read("package.json"));

/**
 * The page's prose with runs of whitespace collapsed, the way a browser lays
 * text out. Content assertions run against this so a phrase that happens to
 * wrap across two source lines still matches.
 */
const prose = index.replace(/\s+/g, " ");

/** Matches every occurrence of one capturing pattern and returns capture one. */
function captureAll(source, pattern) {
    return Array.from(source.matchAll(pattern), (match) => match[1]);
}

/** Attribute references that make the browser fetch a subresource. */
function subresourceReferences(html) {
    return [
        ...captureAll(html, /<link\b[^>]*\bhref="([^"]+)"/g),
        ...captureAll(html, /<script\b[^>]*\bsrc="([^"]+)"/g),
        ...captureAll(html, /<img\b[^>]*\bsrc="([^"]+)"/g),
        ...captureAll(html, /\bsrcset="([^"]+)"/g),
    ];
}

describe("package layout", () => {
    test("is a private workspace package with a deterministic test script", () => {
        assert.equal(manifest.name, "@slopus/murmur-site");
        assert.equal(manifest.private, true);
        assert.equal(manifest.scripts.test, 'node --test "tests/**/*.test.js"');
        assert.equal(manifest.dependencies, undefined);
        assert.equal(manifest.devDependencies, undefined);
    });

    test("every directory carries a README", () => {
        const directories = [packageRoot, sourcesRoot, join(packageRoot, "tests")];
        for (const directory of directories) {
            const readme = join(directory, "README.md");
            assert.ok(statSync(readme).isFile(), `missing README.md in ${directory}`);
        }
    });

    test("sources contains only the expected static assets", () => {
        assert.deepEqual(readdirSync(sourcesRoot).sort(), [
            "404.html",
            "README.md",
            "_headers",
            "index.html",
            "site.css",
            "site.js",
        ]);
    });
});

describe("worker configuration", () => {
    const raw = read("wrangler.production.jsonc");
    const config = JSON.parse(raw.replace(/^\s*\/\/.*$/gm, "").replace(/,(\s*[}\]])/g, "$1"));

    test("is an assets-only Worker named murmur", () => {
        assert.equal(config.name, "murmur");
        assert.equal(config.main, undefined, "an assets-only Worker must not declare a script");
        assert.equal(config.assets.directory, "./sources");
        assert.equal(config.assets.not_found_handling, "404-page");
    });

    test("declares no bindings, secrets, or server state", () => {
        for (const key of [
            "durable_objects",
            "kv_namespaces",
            "d1_databases",
            "r2_buckets",
            "vars",
        ]) {
            assert.equal(config[key], undefined, `unexpected ${key} binding`);
        }
    });
});

describe("security headers", () => {
    test("denies every fetch directive by default and allows only same-origin code", () => {
        assert.match(headers, /Content-Security-Policy:.*default-src 'none'/);
        assert.match(headers, /Content-Security-Policy:.*script-src 'self'/);
        assert.match(headers, /Content-Security-Policy:.*style-src 'self'/);
        assert.match(headers, /Content-Security-Policy:.*connect-src 'none'/);
        assert.match(headers, /Content-Security-Policy:.*frame-ancestors 'none'/);
        assert.match(headers, /Content-Security-Policy:.*base-uri 'none'/);
        assert.match(headers, /Content-Security-Policy:.*object-src 'none'/);
    });

    test("sets the remaining transport and sniffing protections", () => {
        assert.match(headers, /Strict-Transport-Security: max-age=\d+/);
        assert.match(headers, /X-Content-Type-Options: nosniff/);
        assert.match(headers, /Referrer-Policy: no-referrer/);
        assert.match(headers, /X-Frame-Options: DENY/);
        assert.match(headers, /Permissions-Policy:/);
    });

    test("the policy admits no inline script or style, and the pages use none", () => {
        assert.doesNotMatch(headers, /'unsafe-inline'|'unsafe-eval'/);
        for (const [name, html] of [
            ["index.html", index],
            ["404.html", notFound],
        ]) {
            assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)/, `inline <script> in ${name}`);
            assert.doesNotMatch(html, /\sstyle="/, `inline style attribute in ${name}`);
            assert.doesNotMatch(html, /<style\b/, `inline <style> in ${name}`);
        }
    });
});

describe("no external runtime assets", () => {
    test("every subresource is a local absolute path that exists on disk", () => {
        for (const [name, html] of [
            ["index.html", index],
            ["404.html", notFound],
        ]) {
            const references = subresourceReferences(html);
            assert.ok(references.length > 0, `${name} loads no subresources at all`);
            for (const reference of references) {
                assert.ok(reference.startsWith("/"), `${name} loads non-local ${reference}`);
                assert.ok(
                    statSync(join(sourcesRoot, reference.slice(1))).isFile(),
                    `${name} references missing ${reference}`,
                );
            }
        }
    });

    test("no embedded third-party frames or media", () => {
        for (const html of [index, notFound]) {
            assert.doesNotMatch(html, /<(iframe|object|embed|video|audio)\b/);
        }
    });

    test("the stylesheet imports nothing and bundles no font", () => {
        assert.doesNotMatch(css, /@import/);
        assert.doesNotMatch(css, /@font-face/);
        assert.doesNotMatch(css, /url\(/);
    });

    test("the script performs no network access", () => {
        assert.doesNotMatch(
            script,
            /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|import\s*\(/,
        );
        assert.doesNotMatch(script, /https?:\/\//);
    });

    test("no analytics or tracking vendor appears anywhere", () => {
        const vendors = [
            "google-analytics",
            "googletagmanager",
            "gtag(",
            "plausible",
            "posthog",
            "mixpanel",
            "segment.com",
            "hotjar",
            "fullstory",
            "sentry",
        ];
        for (const source of [index, notFound, css, script, headers]) {
            for (const vendor of vendors) {
                assert.ok(!source.includes(vendor), `analytics vendor ${vendor} referenced`);
            }
        }
    });
});

describe("accessibility landmarks and structure", () => {
    test("declares a language and exactly one first-level heading", () => {
        assert.match(index, /<html lang="en">/);
        assert.equal(index.split("<h1").length - 1, 1, "expected exactly one <h1>");
    });

    test("provides banner, navigation, main, and contentinfo landmarks", () => {
        assert.match(index, /<header class="chrome">/);
        assert.match(index, /<nav class="chrome-nav" aria-label="Sections">/);
        assert.match(index, /<main id="main">/);
        assert.match(index, /<footer class="site-footer">/);
    });

    test("a skip link targets the main landmark", () => {
        assert.match(index, /<a class="skip-link" href="#main">/);
    });

    test("every element id is unique", () => {
        const ids = captureAll(index, /\bid="([^"]+)"/g);
        assert.equal(new Set(ids).size, ids.length, "duplicate id attribute");
    });

    test("list item tags remain balanced", () => {
        assert.equal(index.match(/<li\b/g)?.length, index.match(/<\/li>/g)?.length);
    });

    test("every section is named by an existing heading id", () => {
        const ids = new Set(captureAll(index, /\bid="([^"]+)"/g));
        const labels = captureAll(index, /<section\b[^>]*\baria-labelledby="([^"]+)"/g);
        assert.equal(
            labels.length,
            index.split("<section").length - 1,
            "every <section> must carry aria-labelledby",
        );
        for (const label of labels) {
            for (const token of label.split(/\s+/)) {
                assert.ok(ids.has(token), `aria-labelledby points at missing id ${token}`);
            }
        }
    });

    test("every in-page anchor resolves to an existing id", () => {
        const ids = new Set(captureAll(index, /\bid="([^"]+)"/g));
        for (const href of captureAll(index, /\bhref="#([^"]+)"/g)) {
            assert.ok(ids.has(href), `dead in-page anchor #${href}`);
        }
    });

    test("the tab set is wired in both directions", () => {
        const tabs = Array.from(index.matchAll(/<button\b[^>]*role="tab"[^>]*>/g), (m) => m[0]);
        assert.ok(tabs.length >= 2, "expected a multi-tab code panel");

        const ids = new Set(captureAll(index, /\bid="([^"]+)"/g));
        let selected = 0;
        for (const tab of tabs) {
            const controls = /\baria-controls="([^"]+)"/.exec(tab);
            assert.ok(controls !== null && ids.has(controls[1]), "tab controls a missing panel");
            assert.match(tab, /\baria-selected="(true|false)"/);
            if (tab.includes('aria-selected="true"')) selected += 1;
        }
        assert.equal(selected, 1, "exactly one tab must start selected");

        const panels = captureAll(
            index,
            /<div\b[^>]*role="tabpanel"[^>]*\baria-labelledby="([^"]+)"/g,
        );
        assert.equal(panels.length, tabs.length);
        for (const label of panels) assert.ok(ids.has(label), `panel names missing tab ${label}`);
    });

    test("every button declares a type and every abbreviation a title", () => {
        for (const button of captureAll(index, /(<button\b[^>]*>)/g)) {
            assert.match(button, /\btype="button"/);
        }
        for (const abbreviation of captureAll(index, /(<abbr\b[^>]*>)/g)) {
            assert.match(abbreviation, /\btitle="/);
        }
    });

    test("every off-site link carries rel=noreferrer", () => {
        for (const anchor of captureAll(index, /(<a\b[^>]*href="https?:[^"]*"[^>]*>)/g)) {
            assert.match(anchor, /\brel="noreferrer"/, `missing rel on ${anchor}`);
        }
    });
});

describe("visual system", () => {
    test("uses no gradient, and no colour literal outside a token declaration", () => {
        assert.doesNotMatch(css, /gradient\(/);
        for (const line of css.split("\n")) {
            if (!/#[0-9a-fA-F]{3,8}\b|\brgb\(/.test(line)) continue;
            assert.match(
                line.trim(),
                /^--[a-z-]+:/,
                `colour literal outside a token: ${line.trim()}`,
            );
        }
    });

    test("keeps Happy's role names and radius scale", () => {
        for (const token of [
            "--text:",
            "--text-secondary:",
            "--text-link:",
            "--surface:",
            "--divider:",
            "--button-primary-background:",
            "--groupped-background:",
        ]) {
            assert.ok(css.includes(token), `missing Happy role ${token}`);
        }
        assert.match(css, /--happy-radius-sm:\s*6px/);
        assert.match(css, /--happy-radius-window:\s*8px/);
        assert.match(css, /--happy-radius-md:\s*10px/);
        assert.match(css, /--happy-radius-shell:\s*14px/);
    });

    test("teal is the link colour and black is the primary action", () => {
        assert.match(css, /--text-link:\s*#2baccc/);
        assert.match(css, /--button-primary-background:\s*#000000/);
    });

    test("ships light and dark without a duplicate themed tree", () => {
        assert.match(css, /@media \(prefers-color-scheme: dark\)/);
        assert.match(css, /\.happy-theme-dark\s*\{/);
        assert.match(css, /\.happy-theme-light\b/);
        assert.match(script, /documentElement/);
    });

    test("spacing stays on the 4px grid", () => {
        for (const value of captureAll(
            css,
            /(?:padding|margin|gap|row-gap|column-gap):\s*([^;]+);/g,
        )) {
            for (const length of value.matchAll(/(-?\d+)px/g)) {
                // A single pixel is the hairline and clip exception the design
                // system allows; every other length is a multiple of four.
                const magnitude = Math.abs(Number(length[1]));
                assert.ok(
                    magnitude <= 1 || magnitude % 4 === 0,
                    `off-grid spacing ${length[0]} in "${value.trim()}"`,
                );
            }
        }
    });

    test("motion is restrained and honours a reduced-motion preference", () => {
        assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
        assert.doesNotMatch(css, /@keyframes/);
        for (const duration of css.matchAll(/(\d+(?:\.\d+)?)ms/g)) {
            assert.ok(Number(duration[1]) <= 200, `motion longer than 200ms: ${duration[0]}`);
        }
    });

    test("focus is always visible", () => {
        assert.match(css, /:focus-visible\s*\{[^}]*outline:/);
    });
});

describe("content: how Murmur works", () => {
    const required = [
        "browser-safe TypeScript library",
        "32-byte Ed25519 public key",
        "X25519 agreement key",
        "KeyPackage",
        "SHA-256 digest",
        "five minutes",
        "epoch committer",
        "TreeKEM",
        "UUIDv7",
        "MurmurStore",
        "durable outboxes",
        "forward-secret",
    ];

    for (const phrase of required) {
        test(`explains "${phrase}"`, () => {
            assert.ok(prose.includes(phrase), `missing "${phrase}"`);
        });
    }

    test("names the four steps", () => {
        for (const step of ["Identity", "Invitation", "Session", "Synchronization"]) {
            assert.match(prose, new RegExp(`<h3>${step}</h3>`));
        }
    });
});

describe("content: invitations and mutual contacts", () => {
    test("describes the mutual contact handshake rather than a friendship object", () => {
        assert.ok(prose.includes("acceptContact()"));
        assert.ok(prose.includes("rejectContact()"));
        assert.ok(prose.includes("mutual exchange confirms the contact"));
        assert.ok(prose.includes('no separate "friendship" object'));
    });

    test("states that contact admission works while the peer is offline", () => {
        assert.ok(prose.includes("fifteen one-use MLS KeyPackages"));
        assert.ok(prose.includes("last-resort package"));
        assert.ok(prose.includes("availability tradeoff"));
    });

    test("states that an invitation is a bearer capability and revocation is relay-dependent", () => {
        assert.ok(prose.includes("bearer capabilities"));
        assert.ok(prose.includes("revokeInvitation(digest)"));
        assert.ok(prose.includes("reachable relay"));
    });
});

describe("content: cryptography references", () => {
    const references = {
        "RFC 9420 (MLS)": "https://www.rfc-editor.org/rfc/rfc9420",
        "RFC 9180 (HPKE)": "https://www.rfc-editor.org/rfc/rfc9180",
        "RFC 7748 (X25519)": "https://www.rfc-editor.org/rfc/rfc7748",
        "RFC 5869 (HKDF)": "https://www.rfc-editor.org/rfc/rfc5869",
        "RFC 8032 (Ed25519)": "https://www.rfc-editor.org/rfc/rfc8032",
        "@noble/curves": "https://github.com/paulmillr/noble-curves",
        "@noble/hashes": "https://github.com/paulmillr/noble-hashes",
        "@noble/ciphers": "https://github.com/paulmillr/noble-ciphers",
    };

    for (const [name, url] of Object.entries(references)) {
        test(`links ${name}`, () => {
            assert.ok(prose.includes(`href="${url}"`), `missing link to ${url}`);
        });
    }

    test("names the exact primitives the library implements", () => {
        for (const primitive of [
            "<code>0x0001</code>",
            "DHKEM(X25519, HKDF-SHA-256)",
            "HKDF-SHA-256",
            "AES-128-GCM",
            "AES-256-GCM",
            "Ed25519",
            "BasicCredential",
            "SHA-256",
        ]) {
            assert.ok(prose.includes(primitive), `missing primitive ${primitive}`);
        }
    });

    test("claims no primitive the library does not use", () => {
        for (const absent of [
            "ChaCha20",
            "Poly1305",
            "XSalsa",
            "RSA",
            "P-256",
            "Signal Protocol",
        ]) {
            assert.ok(!prose.includes(absent), `claims unused primitive ${absent}`);
        }
    });
});

describe("content: relay trust boundary", () => {
    test("separates what the relay sees from what it never receives", () => {
        assert.ok(prose.includes("The relay sees"));
        assert.ok(prose.includes("The relay never receives"));
        for (const visible of [
            "sender and recipient public identities",
            "exact multicast fanout",
            "delivery sizes, timing, TTL",
        ]) {
            assert.ok(prose.includes(visible), `missing relay-visible item: ${visible}`);
        }
        for (const hidden of ["identity roots", "MLS epochs", "application plaintext"]) {
            assert.ok(prose.includes(hidden), `missing relay-hidden item: ${hidden}`);
        }
    });

    test("states the metadata caveat without hedging", () => {
        assert.ok(prose.includes("not communication metadata"));
        assert.ok(
            prose.includes("If you need metadata privacy, Murmur is the wrong layer for it."),
        );
        assert.ok(
            prose.includes("anonymous: the relay learns sender, recipient, fanout, and timing"),
        );
    });

    test("bounds what a hostile relay can do", () => {
        assert.ok(prose.includes("delay, drop, reorder across inboxes, replay"));
        assert.ok(prose.includes("cannot"));
        assert.ok(prose.includes("decrypt MLS content"));
    });
});

describe("content: offline durability", () => {
    test("states the persist-then-acknowledge invariant", () => {
        assert.ok(prose.includes("Persist, then acknowledge."));
        assert.ok(prose.includes("harmless redelivery"));
        assert.ok(prose.includes("At-least-once with stable IDs"));
    });

    test("states that sends never block", () => {
        assert.ok(prose.includes("never waits for the network"));
        assert.ok(prose.includes("staged post-Commit epoch"));
    });

    test("states that the relay is not an archive", () => {
        assert.ok(prose.includes("not an archive"));
        assert.ok(prose.includes("server-side history: acknowledged deliveries are gone"));
    });
});

describe("content: typed services and code", () => {
    test("shows the two-method service contract", () => {
        assert.ok(prose.includes("MurmurService"));
        assert.ok(prose.includes("onNewSession"));
        assert.ok(prose.includes("onUpdate"));
        assert.ok(prose.includes("MurmurClient.open("));
        assert.ok(prose.includes("createSession("));
    });

    test("escapes every code sample so no markup leaks", () => {
        for (const block of captureAll(
            index,
            /<pre class="code"><code>([\s\S]*?)<\/code><\/pre>/g,
        )) {
            assert.doesNotMatch(block, /<[a-zA-Z/]/, "unescaped markup inside a code sample");
        }
    });

    test("warns against applying a service update twice", () => {
        assert.ok(prose.includes("do not apply the update a second time"));
    });
});

describe("content: honest claims", () => {
    test("discloses the audit status", () => {
        assert.ok(prose.includes("has not received an independent security audit"));
        assert.ok(prose.includes("not a claim of complete RFC feature coverage"));
    });

    test("discloses the remaining limits", () => {
        for (const limit of [
            "One active receiving device per identity",
            "No history and no recovery from the relay",
            "non-Sybil admission control",
            "no hosted public relay",
        ]) {
            assert.ok(prose.includes(limit), `missing limit: ${limit}`);
        }
    });

    test("makes no absolute security claim", () => {
        const forbidden = [
            "zero-knowledge",
            "zero knowledge",
            "military-grade",
            "military grade",
            "unbreakable",
            "unhackable",
            "NSA-proof",
            "100% secure",
            "completely private",
            "perfect secrecy",
            "we cannot see",
            "we can't see",
            "trustless",
        ];
        const lower = prose.toLowerCase();
        for (const claim of forbidden) {
            assert.ok(!lower.includes(claim.toLowerCase()), `misleading claim: ${claim}`);
        }
    });
});

describe("content: install and repository links", () => {
    test("shows the install command and the local relay recipe", () => {
        assert.ok(prose.includes("pnpm add @slopus/murmur"));
        assert.ok(prose.includes("MURMUR_RELAY_STORE=sqlite"));
        assert.ok(prose.includes("require TLS termination"));
    });

    test("links the repository, the package, and every reference document", () => {
        for (const url of [
            "https://github.com/slopus/murmur",
            "https://www.npmjs.com/package/@slopus/murmur",
            "https://github.com/slopus/murmur/blob/main/docs/ARCHITECTURE.md",
            "https://github.com/slopus/murmur/blob/main/docs/PROTOCOL.md",
            "https://github.com/slopus/murmur/blob/main/docs/RELAY_API.md",
            "https://github.com/slopus/murmur/blob/main/docs/SECURITY.md",
            "https://github.com/slopus/murmur/blob/main/LICENSE",
        ]) {
            assert.ok(prose.includes(`href="${url}"`), `missing link to ${url}`);
        }
    });
});

describe("the 404 page", () => {
    test("shares the stylesheet, the landmarks, and a way back", () => {
        assert.match(notFound, /<html lang="en">/);
        assert.match(notFound, /<main id="main">/);
        assert.match(notFound, /href="\/site\.css"/);
        assert.match(notFound, /href="\/"/);
        assert.equal(notFound.split("<h1").length - 1, 1);
    });
});
