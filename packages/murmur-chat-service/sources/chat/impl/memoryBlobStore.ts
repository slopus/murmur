import { sha256 } from "@noble/hashes/sha256";
import type { BlobHead, BlobStore } from "../types.js";
import { ensureNotAborted, equalBytes, encodeBase64Url } from "./bytes.js";
import { HASH_BYTES, MAXIMUM_ATTACHMENT_BYTES, TAG_BYTES } from "./codec.js";

const MAXIMUM_CIPHERTEXT_BYTES =
    MAXIMUM_ATTACHMENT_BYTES + Math.ceil(MAXIMUM_ATTACHMENT_BYTES / (256 * 1024)) * TAG_BYTES;

/** Browser-safe ephemeral immutable blob backend for tests and development. */
export class MemoryBlobStore implements BlobStore {
    readonly #values = new Map<string, Uint8Array>();

    /** Verify identifier, exact length, and immutable/idempotent semantics. */
    async put(
        blobId: Uint8Array,
        byteLength: number,
        bytes: AsyncIterable<Uint8Array>,
        signal: AbortSignal,
    ): Promise<void> {
        validateBlobId(blobId);
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > MAXIMUM_CIPHERTEXT_BYTES
        ) {
            throw new Error("Invalid blob length");
        }
        ensureNotAborted(signal);
        const result = new Uint8Array(byteLength);
        let offset = 0;
        for await (const part of bytes) {
            ensureNotAborted(signal);
            if (!(part instanceof Uint8Array) || part.length > byteLength - offset) {
                result.fill(0);
                throw new Error("Blob stream exceeds declared length");
            }
            result.set(part, offset);
            offset += part.length;
        }
        if (offset !== byteLength || !equalBytes(sha256(result), blobId)) {
            result.fill(0);
            throw new Error("Blob stream length or SHA-256 does not match blobId");
        }
        const key = encodeBase64Url(blobId);
        const existing = this.#values.get(key);
        if (existing !== undefined && !equalBytes(existing, result)) {
            result.fill(0);
            throw new Error("Immutable blob collision");
        }
        if (existing === undefined) this.#values.set(key, result);
        else result.fill(0);
    }

    /** Return exact blob length. */
    async head(blobId: Uint8Array, signal: AbortSignal): Promise<BlobHead | undefined> {
        validateBlobId(blobId);
        ensureNotAborted(signal);
        const value = this.#values.get(encodeBase64Url(blobId));
        return value === undefined ? undefined : { byteLength: value.length };
    }

    /** Return an exact defensive range. */
    async get(
        blobId: Uint8Array,
        offset: number,
        byteLength: number,
        signal: AbortSignal,
    ): Promise<Uint8Array> {
        validateBlobId(blobId);
        ensureNotAborted(signal);
        const value = this.#values.get(encodeBase64Url(blobId));
        if (
            value === undefined ||
            !Number.isSafeInteger(offset) ||
            !Number.isSafeInteger(byteLength) ||
            offset < 0 ||
            byteLength < 0 ||
            offset + byteLength > value.length
        ) {
            throw new Error("Blob range is unavailable");
        }
        return value.slice(offset, offset + byteLength);
    }

    /** Delete one blob when explicitly requested by the application. */
    async delete(blobId: Uint8Array, signal: AbortSignal): Promise<void> {
        validateBlobId(blobId);
        ensureNotAborted(signal);
        const key = encodeBase64Url(blobId);
        this.#values.get(key)?.fill(0);
        this.#values.delete(key);
    }
}

function validateBlobId(blobId: Uint8Array): void {
    if (!(blobId instanceof Uint8Array) || blobId.length !== HASH_BYTES) {
        throw new Error("blobId must contain 32 bytes");
    }
}
