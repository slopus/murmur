import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const packageDirectory =
    process.env.MURMUR_PACKAGE_DIRECTORY ?? fileURLToPath(new URL("..", import.meta.url));
const typescriptBin = fileURLToPath(new URL("../node_modules/typescript/bin/tsc", import.meta.url));

interface PublishedManifest {
    readonly main: string;
    readonly types: string;
    readonly files: readonly string[];
    readonly exports: Readonly<Record<string, unknown>>;
    readonly bin?: unknown;
}

async function publishedManifest(): Promise<PublishedManifest> {
    const require = createRequire(join(packageDirectory, "package.json"));
    const manifestPath = require.resolve("@slopus/murmur/package.json");
    return JSON.parse(await readFile(manifestPath, "utf8")) as PublishedManifest;
}

async function publishedManifestPath(): Promise<string> {
    const require = createRequire(join(packageDirectory, "package.json"));
    return require.resolve("@slopus/murmur/package.json");
}

describe("published package compatibility", () => {
    it("has the exact root-only package export map", async () => {
        const manifest = await publishedManifest();
        expect(Object.keys(manifest.exports).sort()).toEqual([".", "./package.json"]);
        expect(manifest.exports["."]).toEqual({
            types: "./dist/index.d.ts",
            import: "./dist/index.js",
        });
        expect(manifest.exports["./package.json"]).toBe("./package.json");
        expect(manifest.main).toBe("./dist/index.js");
        expect(manifest.types).toBe("./dist/index.d.ts");
        expect(manifest.files).toEqual(["dist", "LICENSE", "README.md", "package.json"]);
        expect(manifest.bin).toBeUndefined();
    });

    it("loads only the supported root API in Node", async () => {
        const script = `
const loaded = await import("@slopus/murmur");
const names = Object.keys(loaded).sort();
if (JSON.stringify(names) !== JSON.stringify([
    "CONTACT_ADMISSION_LOW_WATERMARK",
    "CONTACT_ADMISSION_MAXIMUM_KEY_PACKAGES",
    "CONTACT_ADMISSION_TARGET_KEY_PACKAGES",
    "DISCOVERY_INVITATION_TTL_MILLISECONDS",
    "DeliveryAcknowledgementFutureError",
    "DeliveryCursorTrimmedError",
    "DeliveryTransportError",
    "DiscoveryTransportError",
    "HttpDeliveryTransport",
    "HttpDiscoveryTransport",
    "HttpRelaySessionProvider",
    "InboxProcessor",
    "InboxStateRollbackError",
    "MAXIMUM_STORE_SCAN_ITEMS",
    "MemoryMurmurStore",
    "MurmurClient",
    "OversizedInboxDeliveryError",
    "TerminalInboxDeliveryError",
    "WebSocketDeliveryTransport",
    "contactSessionDescriptor",
    "containsRecipient",
    "createDiscoveryBundle",
    "createMurmurServiceSessionDescriptor",
    "createSignedDelivery",
    "createSignedInboxAck",
    "createSignedInboxRead",
    "createSignedRelaySessionRequest",
    "decodeContactPacket",
    "decodeContactSessionDescriptor",
    "decodeIdentityRoot",
    "destroyIdentity",
    "encodeContactPacket",
    "encodeIdentityRoot",
    "generateIdentityKeyPair",
    "importIdentityKeyPair",
    "isContactSessionDescriptor",
    "parseDiscoveryBundle",
    "parseInboxPage",
    "parseRelaySessionTicket",
    "parseSignedDelivery",
    "parseSignedRelaySessionRequest",
    "serializeDiscoveryBundle",
    "signedDeliveryToJson",
    "signedInboxAckToJson",
    "signedInboxReadToJson",
    "signedRelaySessionRequestToJson",
    "validateContactAdmission",
    "validateContactProfile",
    "validateMurmurServiceRegistration",
    "validateServiceId",
    "validateSignedDelivery",
    "verifyDiscoveryBundle",
    "verifySignedDelivery",
    "verifySignedRelaySessionRequest",
])) {
    throw new Error(\`Unexpected runtime exports: \${names.join(", ")}\`);
}
`;
        await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], {
            cwd: packageDirectory,
        });
    });

    it("blocks every legacy package subpath", async () => {
        const script = `
const blocked = [
    "@slopus/murmur/client",
    "@slopus/murmur/crypto",
    "@slopus/murmur/document",
    "@slopus/murmur/identity",
    "@slopus/murmur/mls",
    "@slopus/murmur/sharedSession",
    "@slopus/murmur/storage",
    "@slopus/murmur/transport",
];
for (const specifier of blocked) {
    let rejected = false;
    try {
        await import(specifier);
    } catch {
        rejected = true;
    }
    if (!rejected) {
        throw new Error(\`Legacy package subpath resolved: \${specifier}\`);
    }
}
`;
        await execFileAsync(process.execPath, ["--input-type=module", "--eval", script], {
            cwd: packageDirectory,
        });
    });

    it("contains no packed legacy CLI, document, session, or package-root MLS artifact", async () => {
        const manifestPath = await publishedManifestPath();
        const root = join(manifestPath, "..");
        const entries = (await readdir(root, { recursive: true })).map((entry) =>
            entry.replaceAll("\\", "/"),
        );
        expect(
            entries.filter((entry) =>
                /^(?:mls|sharedSession)(?:\/|$)|^dist\/(?:cli|client|document|sharedSession|groupChannel|ephemeral)(?:\/|\.)/.test(
                    entry,
                ),
            ),
        ).toEqual([]);
        if (process.env.MURMUR_PACKAGE_DIRECTORY !== undefined) {
            expect(entries.filter((entry) => !entry.includes("/")).sort()).toEqual([
                "LICENSE",
                "README.md",
                "dist",
                "package.json",
            ]);
        }
    });

    it("compiles a strict TypeScript consumer against only the root", async () => {
        const consumerDirectory = await mkdtemp(join(packageDirectory, ".murmur-consumer-"));
        try {
            const manifestPath = await publishedManifestPath();
            await writeFile(
                join(consumerDirectory, "consumer.ts"),
                `
import {
    HttpDeliveryTransport,
    HttpDiscoveryTransport,
    HttpRelaySessionProvider,
    MemoryMurmurStore,
    MurmurClient,
    WebSocketDeliveryTransport,
    destroyIdentity,
    generateIdentityKeyPair,
    type DeliveryFetch,
    type DiscoveryBundle,
    type DiscoveryTransport,
    type IdentityKeyPair,
    type MurmurClientOptions,
    type MurmurContactProfile,
    type MurmurService,
    type MurmurSyncOptions,
    type MurmurSessionPage,
    type MurmurStore,
    type RelaySessionProvider,
    type RelaySessionTicket,
    type SignedRelaySessionRequest,
} from "@slopus/murmur";

const store: MurmurStore = new MemoryMurmurStore();
const deliveryFetch: DeliveryFetch = globalThis.fetch;
const transport = new HttpDeliveryTransport("https://relay.example", { fetch: deliveryFetch });
const discoveryTransport: DiscoveryTransport = new HttpDiscoveryTransport(
    "https://relay.example",
    { fetch: deliveryFetch },
);
const identity: IdentityKeyPair = generateIdentityKeyPair();
const sessionProvider: RelaySessionProvider = new HttpRelaySessionProvider(
    "https://app.example/murmur/session",
    { fetch: deliveryFetch },
);
const negotiatedOptions: MurmurClientOptions = { sessionProvider, store };
const ticket: RelaySessionTicket | undefined = undefined;
const proof: SignedRelaySessionRequest | undefined = undefined;
const options: MurmurClientOptions = {
    relay: new URL("https://relay.example"),
    store,
    fetch: deliveryFetch,
    identity,
    services: [{
        id: "notes",
        service: {
            onNewSession: async () => true,
            onUpdate: async () => {},
        },
    }],
};
const service: MurmurService = options.services![0]!.service;
const profile: MurmurContactProfile = { displayName: "Alice" };
const opening: Promise<MurmurClient> = MurmurClient.open(options);
const syncOptions: MurmurSyncOptions = {
    abort: new AbortController().signal,
    onUpdates: async (updates) => void updates,
};
const page: MurmurSessionPage | undefined = undefined;
const discovery: DiscoveryBundle | undefined = undefined;
void transport;
void discoveryTransport;
void opening;
void syncOptions;
void page;
void discovery;
void service;
void profile;
void negotiatedOptions;
void ticket;
void proof;
void WebSocketDeliveryTransport;
destroyIdentity(identity);
`,
                "utf8",
            );
            await writeFile(
                join(consumerDirectory, "tsconfig.json"),
                JSON.stringify({
                    compilerOptions: {
                        exactOptionalPropertyTypes: true,
                        lib: ["ES2023", "DOM", "DOM.Iterable"],
                        module: "NodeNext",
                        moduleResolution: "NodeNext",
                        noEmit: true,
                        noUncheckedIndexedAccess: true,
                        skipLibCheck: false,
                        strict: true,
                        target: "ES2023",
                        types: [],
                        ...(process.env.MURMUR_PACKAGE_DIRECTORY === undefined
                            ? {
                                  baseUrl: ".",
                                  paths: {
                                      "@slopus/murmur": [
                                          join(manifestPath, "..", "dist", "index.d.ts"),
                                      ],
                                  },
                              }
                            : {}),
                    },
                    include: ["consumer.ts"],
                }),
                "utf8",
            );
            await execFileAsync(process.execPath, [typescriptBin, "-p", "tsconfig.json"], {
                cwd: consumerDirectory,
            });
        } finally {
            await rm(consumerDirectory, { recursive: true, force: true });
        }
    });

    it("executes a browser bundle with no Node import form", async () => {
        const result = await build({
            absWorkingDir: packageDirectory,
            bundle: true,
            format: "iife",
            logLevel: "silent",
            platform: "browser",
            stdin: {
                contents:
                    'import { MemoryMurmurStore, MurmurClient } from "@slopus/murmur";\n' +
                    "globalThis.__MURMUR_PACKAGE_EXPORTS__ = { MemoryMurmurStore, MurmurClient };",
                loader: "js",
                resolveDir: packageDirectory,
                sourcefile: "murmur-browser-smoke.js",
            },
            target: "es2022",
            write: false,
        });
        expect(result.outputFiles).toHaveLength(1);
        const output = result.outputFiles[0]?.text;
        expect(output?.length).toBeGreaterThan(1_000);
        expect(output).not.toMatch(
            /(?:\bfrom\s*|\bimport\s*(?:\(|["'])|\brequire(?:\.resolve)?\s*\()\s*["'`]node:[^"'`]+["'`]/,
        );
        const browser: Record<string, unknown> = {
            AbortController,
            TextDecoder,
            TextEncoder,
            URL,
            Uint8Array,
            crypto: globalThis.crypto,
            fetch: globalThis.fetch,
            setTimeout,
            clearTimeout,
        };
        runInNewContext(output ?? "", browser);
        const exports = browser.__MURMUR_PACKAGE_EXPORTS__ as
            | Readonly<Record<string, unknown>>
            | undefined;
        expect(Object.keys(exports ?? {}).sort()).toEqual(["MemoryMurmurStore", "MurmurClient"]);
        expect(typeof exports?.MemoryMurmurStore).toBe("function");
        expect(typeof exports?.MurmurClient).toBe("function");
    }, 30_000);
});
