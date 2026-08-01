import { randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { link, mkdir, stat, unlink } from "node:fs/promises";
import { Readable, Transform, type TransformCallback } from "node:stream";
import { pipeline } from "node:stream/promises";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { RelayError } from "../../protocol/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";
import { isBlobId } from "../blobId.js";
import type { BlobBackend, BlobLink } from "../types.js";

const DEFAULT_LINK_LIFETIME_MILLISECONDS = 5 * 60 * 1_000;
const encoder = new TextEncoder();

class BlobSizeLimitError extends Error {}

/** Construction options for relay-local filesystem blob storage. */
export interface LocalBlobBackendOptions {
    /** Root beneath which content-addressed files and temporary uploads live. */
    readonly rootDirectory: string;
    /** HMAC secret with at least 256 bits of entropy. */
    readonly secret: Uint8Array;
    /** Signed-link lifetime. Defaults to five minutes. */
    readonly linkLifetimeMilliseconds?: number;
}

function positiveSafeInteger(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive safe integer`);
    }
    return value;
}

function canonicalLinkBytes(method: "PUT" | "GET", id: string, expiresAt: number): Uint8Array {
    return encoder.encode(`murmur-blob-link-v1\n${method}\n${id}\n${expiresAt.toString()}`);
}

function filesystemErrorCode(error: unknown): string | undefined {
    if (typeof error !== "object" || error === null || !("code" in error)) {
        return undefined;
    }
    return typeof error.code === "string" ? error.code : undefined;
}

function contentLength(request: Request, maximumBytes: number): void {
    const value = request.headers.get("content-length");
    if (value === null) {
        return;
    }
    if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
        throw new RelayError(400, "Invalid Content-Length", { error: "malformed" });
    }
    if (BigInt(value) > BigInt(maximumBytes)) {
        throw new RelayError(413, "Blob exceeds relay limit", { error: "limit" });
    }
}

async function filesEqual(leftPath: string, rightPath: string): Promise<boolean> {
    const [leftStat, rightStat] = await Promise.all([stat(leftPath), stat(rightPath)]);
    if (!leftStat.isFile() || !rightStat.isFile() || leftStat.size !== rightStat.size) {
        return false;
    }
    const left = createReadStream(leftPath);
    const right = createReadStream(rightPath);
    const leftIterator = left[Symbol.asyncIterator]();
    const rightIterator = right[Symbol.asyncIterator]();
    try {
        for (;;) {
            const [leftChunk, rightChunk] = await Promise.all([
                leftIterator.next(),
                rightIterator.next(),
            ]);
            if (leftChunk.done || rightChunk.done) {
                return leftChunk.done === rightChunk.done;
            }
            if (
                !(leftChunk.value instanceof Uint8Array) ||
                !(rightChunk.value instanceof Uint8Array) ||
                !equalBytes(leftChunk.value, rightChunk.value)
            ) {
                return false;
            }
        }
    } finally {
        left.destroy();
        right.destroy();
    }
}

/**
 * Filesystem blob backend with HMAC-authenticated relay-local transfer links.
 *
 * Uploads are streamed into same-directory temporary files and atomically
 * installed only after their SHA-256 identifier has been verified.
 */
export class LocalBlobBackend implements BlobBackend {
    readonly #rootDirectory: string;
    readonly #secret: Uint8Array;
    readonly #linkLifetimeMilliseconds: number;
    readonly #activeUploads = new Set<Promise<void>>();
    #closed = false;

    constructor(options: LocalBlobBackendOptions) {
        if (options.rootDirectory.length === 0) {
            throw new Error("Local blob root directory cannot be empty");
        }
        if (!(options.secret instanceof Uint8Array) || options.secret.length < 32) {
            throw new Error("Local blob secret must contain at least 32 bytes");
        }
        this.#rootDirectory = options.rootDirectory;
        this.#secret = options.secret.slice();
        this.#linkLifetimeMilliseconds = positiveSafeInteger(
            options.linkLifetimeMilliseconds ?? DEFAULT_LINK_LIFETIME_MILLISECONDS,
            "Blob link lifetime",
        );
    }

    /** Issue one signed relay-local upload link. */
    async createUploadLink(id: string, now: number): Promise<BlobLink> {
        this.#assertOpen();
        this.#validateLinkInput(id, now);
        return this.#createLink("PUT", id, now);
    }

    /** Issue one signed relay-local download link when the blob exists. */
    async createDownloadLink(id: string, now: number): Promise<BlobLink | undefined> {
        this.#assertOpen();
        this.#validateLinkInput(id, now);
        try {
            const metadata = await stat(this.#blobPath(id));
            return metadata.isFile() ? this.#createLink("GET", id, now) : undefined;
        } catch (error) {
            if (filesystemErrorCode(error) === "ENOENT") {
                return undefined;
            }
            throw error;
        }
    }

    /** Authenticate and stream one relay-local PUT or GET transfer. */
    async handleTransfer(
        request: Request,
        id: string,
        now: number,
        maximumBytes: number,
    ): Promise<Response> {
        this.#assertOpen();
        positiveSafeInteger(maximumBytes, "Maximum blob bytes");
        const method = request.method;
        if (method !== "PUT" && method !== "GET") {
            throw new RelayError(401, "Blob link method is not authorized", {
                error: "unauthorized",
            });
        }
        this.#verifyLink(request, method, id, now);
        if (method === "GET") {
            return this.#download(id, maximumBytes);
        }
        const upload = this.#upload(request, id, maximumBytes);
        this.#activeUploads.add(upload);
        try {
            await upload;
        } finally {
            this.#activeUploads.delete(upload);
        }
        return new Response(null, { status: 204 });
    }

    /** Stop accepting work and wait for active uploads before clearing the secret copy. */
    async close(): Promise<void> {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        await Promise.allSettled(this.#activeUploads);
        this.#secret.fill(0);
    }

    #createLink(method: "PUT" | "GET", id: string, now: number): BlobLink {
        const expiresAt = now + this.#linkLifetimeMilliseconds;
        if (!Number.isSafeInteger(expiresAt)) {
            throw new Error("Blob link expiry exceeds JavaScript's safe integer range");
        }
        const signature = encodeBase64Url(
            hmac(sha256, this.#secret, canonicalLinkBytes(method, id, expiresAt)),
        );
        const parameters = new URLSearchParams({
            expires: expiresAt.toString(),
            signature,
        });
        return {
            url: `/v1/blobs/${encodeURIComponent(id)}?${parameters.toString()}`,
            method,
            expiresAt,
            ...(method === "PUT"
                ? { headers: { "content-type": "application/octet-stream" } }
                : {}),
        };
    }

    #verifyLink(request: Request, method: "PUT" | "GET", id: string, now: number): void {
        if (!isBlobId(id)) {
            throw new RelayError(400, "Invalid blob identifier", { error: "malformed" });
        }
        const url = new URL(request.url);
        const expiresValues = url.searchParams.getAll("expires");
        const signatureValues = url.searchParams.getAll("signature");
        if (
            expiresValues.length !== 1 ||
            signatureValues.length !== 1 ||
            [...url.searchParams.keys()].some((key) => key !== "expires" && key !== "signature")
        ) {
            throw new RelayError(401, "Invalid blob link", { error: "unauthorized" });
        }
        const expires = expiresValues[0];
        const signature = signatureValues[0];
        if (
            expires === undefined ||
            signature === undefined ||
            !/^(?:0|[1-9][0-9]*)$/.test(expires)
        ) {
            throw new RelayError(401, "Invalid blob link", { error: "unauthorized" });
        }
        const expiresAt = Number(expires);
        if (!Number.isSafeInteger(expiresAt)) {
            throw new RelayError(401, "Invalid blob link", { error: "unauthorized" });
        }
        if (now >= expiresAt) {
            throw new RelayError(401, "Blob link has expired", { error: "expired" });
        }
        let suppliedSignature: Uint8Array;
        try {
            suppliedSignature = decodeBase64Url(signature, 32);
        } catch {
            throw new RelayError(401, "Invalid blob link", { error: "unauthorized" });
        }
        const expectedSignature = hmac(
            sha256,
            this.#secret,
            canonicalLinkBytes(method, id, expiresAt),
        );
        if (!equalBytes(suppliedSignature, expectedSignature)) {
            throw new RelayError(401, "Invalid blob link signature", {
                error: "unauthorized",
            });
        }
    }

    async #upload(request: Request, id: string, maximumBytes: number): Promise<void> {
        contentLength(request, maximumBytes);
        const directory = this.#blobDirectory(id);
        await mkdir(directory, { recursive: true });
        const temporaryPath = `${directory}/.${id}.${randomBytes(16).toString("hex")}.tmp`;
        const destinationPath = this.#blobPath(id);
        const digest = sha256.create();
        let receivedBytes = 0;
        const verifier = new Transform({
            transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
                receivedBytes += chunk.length;
                if (receivedBytes > maximumBytes) {
                    callback(new BlobSizeLimitError());
                    return;
                }
                digest.update(chunk);
                callback(null, chunk);
            },
        });
        try {
            const source =
                request.body === null
                    ? Readable.from([])
                    : Readable.fromWeb(request.body as ReadableStream<Uint8Array>);
            try {
                await pipeline(
                    source,
                    verifier,
                    createWriteStream(temporaryPath, { flags: "wx", mode: 0o600 }),
                    { signal: request.signal },
                );
            } catch (error) {
                if (error instanceof BlobSizeLimitError) {
                    throw new RelayError(413, "Blob exceeds relay limit", {
                        error: "limit",
                    });
                }
                throw error;
            }
            const expectedDigest = decodeBase64Url(id, 32);
            if (!equalBytes(digest.digest(), expectedDigest)) {
                throw new RelayError(400, "Blob hash mismatch", {
                    error: "hash_mismatch",
                });
            }
            try {
                await link(temporaryPath, destinationPath);
            } catch (error) {
                if (filesystemErrorCode(error) !== "EEXIST") {
                    throw error;
                }
                if (!(await filesEqual(temporaryPath, destinationPath))) {
                    throw new RelayError(409, "Blob identifier collision", {
                        error: "id_collision",
                    });
                }
            }
        } finally {
            await unlink(temporaryPath).catch((error: unknown) => {
                if (filesystemErrorCode(error) !== "ENOENT") {
                    throw error;
                }
            });
        }
    }

    async #download(id: string, maximumBytes: number): Promise<Response> {
        let metadata;
        try {
            metadata = await stat(this.#blobPath(id));
        } catch (error) {
            if (filesystemErrorCode(error) === "ENOENT") {
                throw new RelayError(404, "Blob not found", { error: "not_found" });
            }
            throw error;
        }
        if (!metadata.isFile()) {
            throw new RelayError(404, "Blob not found", { error: "not_found" });
        }
        if (metadata.size > maximumBytes) {
            throw new RelayError(413, "Blob exceeds relay limit", { error: "limit" });
        }
        return new Response(
            Readable.toWeb(createReadStream(this.#blobPath(id))) as ReadableStream<Uint8Array>,
            {
                status: 200,
                headers: {
                    "content-length": metadata.size.toString(),
                    "content-type": "application/octet-stream",
                },
            },
        );
    }

    #blobDirectory(id: string): string {
        return `${this.#rootDirectory}/${id.slice(0, 2)}/${id.slice(2, 4)}`;
    }

    #blobPath(id: string): string {
        return `${this.#blobDirectory(id)}/${id}`;
    }

    #validateLinkInput(id: string, now: number): void {
        if (!isBlobId(id)) {
            throw new RelayError(400, "Invalid blob identifier", { error: "malformed" });
        }
        if (!Number.isSafeInteger(now) || now < 0) {
            throw new Error("Blob link time must be a non-negative safe integer");
        }
    }

    #assertOpen(): void {
        if (this.#closed) {
            throw new Error("Local blob backend is closed");
        }
    }
}
