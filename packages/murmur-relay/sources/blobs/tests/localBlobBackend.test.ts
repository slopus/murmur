import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRelayFetchHandler, type RelayFetchHandler } from "../../http/index.js";
import { RelayService } from "../../relay/index.js";
import { SqliteRelayStore } from "../../storage/sqlite/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { LocalBlobBackend } from "../index.js";
import type { BlobLink } from "../types.js";

const encoder = new TextEncoder();
const initialNow = 10_000;

function id(bytes: Uint8Array): string {
    return encodeBase64Url(sha256(bytes));
}

async function link(
    handler: RelayFetchHandler,
    blobId: string,
    kind: "upload-link" | "download-link",
): Promise<BlobLink | undefined> {
    const response = await handler(
        new Request(`https://relay.test/v1/blobs/${blobId}/${kind}`, {
            method: "POST",
        }),
    );
    if (response.status === 404) {
        return undefined;
    }
    expect(response.status).toBe(200);
    return (await response.json()) as BlobLink;
}

function linkedRequest(link: BlobLink, body?: Uint8Array): Request {
    return new Request(new URL(link.url, "https://relay.test"), {
        method: link.method,
        ...(link.headers === undefined ? {} : { headers: link.headers }),
        ...(body === undefined ? {} : { body }),
    });
}

describe("LocalBlobBackend", () => {
    let rootDirectory: string;
    let backend: LocalBlobBackend;
    let service: RelayService;
    let handler: RelayFetchHandler;
    let now: number;

    beforeEach(async () => {
        rootDirectory = await mkdtemp(join(tmpdir(), "murmur-blobs-"));
        backend = new LocalBlobBackend({
            rootDirectory,
            secret: new Uint8Array(32).fill(1),
            linkLifetimeMilliseconds: 1_000,
        });
        service = new RelayService(new SqliteRelayStore(":memory:"), {
            rateLimit: false,
            maximumBlobBytes: 64,
        });
        now = initialNow;
        handler = createRelayFetchHandler(service, {
            blobBackend: backend,
            now: () => now,
        });
    });

    afterEach(async () => {
        await backend.close();
        await service.close();
        await rm(rootDirectory, { recursive: true, force: true });
    });

    it("accepts a valid signed upload and download link", async () => {
        const bytes = encoder.encode("ciphertext");
        const blobId = id(bytes);
        const uploadLink = await link(handler, blobId, "upload-link");
        if (uploadLink === undefined) {
            throw new Error("Expected upload link");
        }
        expect((await handler(linkedRequest(uploadLink, bytes))).status).toBe(204);

        const downloadLink = await link(handler, blobId, "download-link");
        if (downloadLink === undefined) {
            throw new Error("Expected download link");
        }
        const download = await handler(linkedRequest(downloadLink));
        expect(download.status).toBe(200);
        expect(new Uint8Array(await download.arrayBuffer())).toEqual(bytes);
    });

    it("rejects expired, tampered-id, wrong-method, and foreign-secret links", async () => {
        const bytes = encoder.encode("auth cases");
        const blobId = id(bytes);
        const uploadLink = await link(handler, blobId, "upload-link");
        if (uploadLink === undefined) {
            throw new Error("Expected upload link");
        }

        now = uploadLink.expiresAt;
        expect((await handler(linkedRequest(uploadLink, bytes))).status).toBe(401);
        now = initialNow;

        const otherId = id(encoder.encode("other"));
        const tamperedUrl = new URL(uploadLink.url, "https://relay.test");
        tamperedUrl.pathname = `/v1/blobs/${otherId}`;
        expect(
            (
                await handler(
                    new Request(tamperedUrl, {
                        method: "PUT",
                        body: bytes,
                    }),
                )
            ).status,
        ).toBe(401);

        expect(
            (
                await handler(
                    new Request(new URL(uploadLink.url, "https://relay.test"), {
                        method: "GET",
                    }),
                )
            ).status,
        ).toBe(401);

        const foreignBackend = new LocalBlobBackend({
            rootDirectory,
            secret: new Uint8Array(32).fill(2),
        });
        const foreignHandler = createRelayFetchHandler(service, {
            blobBackend: foreignBackend,
            now: () => now,
        });
        try {
            expect((await foreignHandler(linkedRequest(uploadLink, bytes))).status).toBe(401);
        } finally {
            await foreignBackend.close();
        }
    });

    it("discards hash mismatches so no download link is issued", async () => {
        const expected = encoder.encode("expected");
        const blobId = id(expected);
        const uploadLink = await link(handler, blobId, "upload-link");
        if (uploadLink === undefined) {
            throw new Error("Expected upload link");
        }
        const upload = await handler(linkedRequest(uploadLink, encoder.encode("tampered")));
        expect(upload.status).toBe(400);
        expect(await link(handler, blobId, "download-link")).toBeUndefined();
    });

    it("aborts oversized streaming uploads and leaves no served file", async () => {
        await backend.close();
        await service.close();
        backend = new LocalBlobBackend({
            rootDirectory,
            secret: new Uint8Array(32).fill(1),
        });
        service = new RelayService(new SqliteRelayStore(":memory:"), {
            rateLimit: false,
            maximumBlobBytes: 4,
        });
        handler = createRelayFetchHandler(service, {
            blobBackend: backend,
            now: () => now,
        });
        const bytes = encoder.encode("oversized");
        const blobId = id(bytes);
        const uploadLink = await link(handler, blobId, "upload-link");
        if (uploadLink === undefined) {
            throw new Error("Expected upload link");
        }
        expect((await handler(linkedRequest(uploadLink, bytes))).status).toBe(413);
        expect(await link(handler, blobId, "download-link")).toBeUndefined();
    });

    it("treats identical re-uploads as a no-op", async () => {
        const bytes = encoder.encode("same");
        const blobId = id(bytes);
        const uploadLink = await link(handler, blobId, "upload-link");
        if (uploadLink === undefined) {
            throw new Error("Expected upload link");
        }
        expect((await handler(linkedRequest(uploadLink, bytes))).status).toBe(204);
        expect((await handler(linkedRequest(uploadLink, bytes))).status).toBe(204);
        expect((await handler(linkedRequest(uploadLink, encoder.encode("different")))).status).toBe(
            400,
        );

        const downloadLink = await link(handler, blobId, "download-link");
        if (downloadLink === undefined) {
            throw new Error("Expected download link");
        }
        const response = await handler(linkedRequest(downloadLink));
        expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
    });

    it("publishes concurrent uploads of the same id safely", async () => {
        const bytes = encoder.encode("concurrent");
        const blobId = id(bytes);
        const uploadLink = await link(handler, blobId, "upload-link");
        if (uploadLink === undefined) {
            throw new Error("Expected upload link");
        }
        const responses = await Promise.all([
            handler(linkedRequest(uploadLink, bytes)),
            handler(linkedRequest(uploadLink, bytes)),
        ]);
        expect(responses.map((response) => response.status)).toEqual([204, 204]);

        const downloadLink = await link(handler, blobId, "download-link");
        if (downloadLink === undefined) {
            throw new Error("Expected download link");
        }
        const response = await handler(linkedRequest(downloadLink));
        expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
    });
});
