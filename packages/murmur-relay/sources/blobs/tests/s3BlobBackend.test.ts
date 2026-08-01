import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, it } from "vitest";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { S3BlobBackend } from "../index.js";

const encoder = new TextEncoder();
const now = Date.UTC(2025, 0, 2, 3, 4, 5);

describe("S3BlobBackend", () => {
    it("issues virtual-hosted links with a signed upload checksum", async () => {
        const requests: Request[] = [];
        const backend = new S3BlobBackend({
            endpoint: "https://storage.test",
            region: "us-east-1",
            bucket: "murmur-blobs",
            accessKeyId: "access",
            secretAccessKey: "secret",
            fetchImplementation: async (input, init) => {
                requests.push(new Request(input, init));
                return new Response(null, { status: 200 });
            },
        });
        const digest = sha256(encoder.encode("ciphertext"));
        const blobId = encodeBase64Url(digest);
        try {
            const upload = await backend.createUploadLink(blobId, now);
            expect(upload.method).toBe("PUT");
            expect(new URL(upload.url).host).toBe("murmur-blobs.storage.test");
            expect(upload.headers).toEqual({
                "x-amz-checksum-sha256": Buffer.from(digest).toString("base64"),
            });
            expect(new URL(upload.url).searchParams.get("X-Amz-SignedHeaders")).toBe(
                "host;x-amz-checksum-sha256",
            );

            const download = await backend.createDownloadLink(blobId, now);
            expect(download?.method).toBe("GET");
            expect(requests).toHaveLength(1);
            expect(requests[0]?.method).toBe("HEAD");
            expect(new URL(requests[0]?.url ?? "").pathname).toBe(`/${blobId}`);
        } finally {
            await backend.close();
        }
    });

    it("returns no download link when a signed HEAD reports missing", async () => {
        const backend = new S3BlobBackend({
            endpoint: "http://minio.test:9000",
            region: "local",
            bucket: "murmur-blobs",
            accessKeyId: "access",
            secretAccessKey: "secret",
            pathStyle: true,
            fetchImplementation: async () => new Response(null, { status: 404 }),
        });
        const blobId = encodeBase64Url(sha256(encoder.encode("missing")));
        try {
            await expect(backend.createDownloadLink(blobId, now)).resolves.toBeUndefined();
        } finally {
            await backend.close();
        }
    });
});
