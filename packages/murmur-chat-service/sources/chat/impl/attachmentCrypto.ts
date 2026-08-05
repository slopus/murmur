import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import type { MurmurStore } from "@slopus/murmur";
import { ChatAttachmentAuthenticationError, ChatAttachmentSourceChangedError } from "../errors.js";
import type { AttachmentSource, BlobStore } from "../types.js";
import {
    abortError,
    bytesFromU32,
    bytesFromU64,
    concatBytes,
    ensureNotAborted,
    equalBytes,
} from "./bytes.js";
import {
    ATTACHMENT_CHUNK_BYTES,
    FILE_ID_BYTES,
    GROUP_ID_BYTES,
    HASH_BYTES,
    IDENTITY_BYTES,
    KEY_BYTES,
    MAXIMUM_ATTACHMENT_BYTES,
    MAXIMUM_FRAME_BYTES,
    type EncodedAttachmentIntent,
    type EncodedManifest,
    TAG_BYTES,
} from "./codec.js";

const KEY_INFO = new TextEncoder().encode("murmur/chat/attachment/content-key/v1");
const AAD_DOMAIN = new TextEncoder().encode("murmur/chat/attachment/chunk/v1");
const COMMITMENT_DOMAIN = new TextEncoder().encode("murmur/chat/attachment/commitment/v1");
const VERSION_AND_CIPHER = new Uint8Array([1, 1]);
const STAGE_PAGE = 64;

/** Hash one source without ever mutating source-owned range buffers. */
export async function hashAttachmentSource(
    source: AttachmentSource,
    signal: AbortSignal,
): Promise<Uint8Array> {
    validateSource(source);
    const hash = sha256.create();
    const count = plaintextChunkCount(source.byteLength);
    for (let index = 0; index < count; index += 1) {
        ensureNotAborted(signal);
        const offset = index * ATTACHMENT_CHUNK_BYTES;
        const length = plaintextChunkLength(source.byteLength, index);
        const owned = await readOwnedSourceRange(source, offset, length, signal);
        try {
            hash.update(owned);
        } finally {
            owned.fill(0);
        }
    }
    return hash.digest();
}

/**
 * Encrypt a source exactly once into durable ciphertext staging.
 *
 * The caller persists `stageState: "staging"` before entering. A crash in
 * this function requires rotating fileId/fileKey before any later restage.
 */
export async function stageAttachment(
    source: AttachmentSource,
    intent: EncodedAttachmentIntent,
    conversationId: Uint8Array,
    sender: Uint8Array,
    store: MurmurStore,
    stagePrefix: string,
    signal: AbortSignal,
): Promise<EncodedManifest> {
    validateSource(source);
    validateBindings(conversationId, sender);
    if (source.sourceId !== intent.sourceId || source.byteLength !== intent.plaintextLength) {
        throw new ChatAttachmentSourceChangedError("Attachment source identity or length changed");
    }
    const count = plaintextChunkCount(source.byteLength);
    const key = deriveContentKey(intent.fileKey, intent.fileId);
    const sourceDigest = sha256.create();
    const ciphertextDigest = sha256.create();
    try {
        for (let index = 0; index < count; index += 1) {
            ensureNotAborted(signal);
            const offset = index * ATTACHMENT_CHUNK_BYTES;
            const length = plaintextChunkLength(source.byteLength, index);
            const plaintext = await readOwnedSourceRange(source, offset, length, signal);
            sourceDigest.update(plaintext);
            const nonce = chunkNonce(index);
            const aad = chunkAad(
                conversationId,
                sender,
                intent.fileId,
                source.byteLength,
                count,
                index,
            );
            let ciphertext: Uint8Array | undefined;
            try {
                ciphertext = chacha20poly1305(key, nonce, aad).encrypt(plaintext);
                ciphertextDigest.update(ciphertext);
                await store.set(stageChunkKey(stagePrefix, index), ciphertext);
            } finally {
                plaintext.fill(0);
                nonce.fill(0);
                aad.fill(0);
                ciphertext?.fill(0);
            }
        }
        const observedSourceHash = sourceDigest.digest();
        try {
            if (!equalBytes(observedSourceHash, intent.sourceHash)) {
                throw new ChatAttachmentSourceChangedError(
                    "Attachment source changed during encryption",
                );
            }
        } finally {
            observedSourceHash.fill(0);
        }
        const blobId = ciphertextDigest.digest();
        const commitment = keyCommitment(
            intent.fileKey,
            intent.fileId,
            conversationId,
            sender,
            source.byteLength,
            count,
        );
        return {
            metadata: intent.metadata.slice(),
            fileId: intent.fileId.slice(),
            fileKey: intent.fileKey.slice(),
            commitment,
            blobId,
            plaintextLength: source.byteLength,
            chunkSize: ATTACHMENT_CHUNK_BYTES,
            chunkCount: count,
        };
    } finally {
        key.fill(0);
    }
}

/**
 * Always PUT exact staged bytes, then verify head, every range, and full hash.
 * A hostile or stale `head` response is never treated as proof of presence.
 */
export async function uploadStagedAttachment(
    manifest: EncodedManifest,
    store: MurmurStore,
    stagePrefix: string,
    blobStore: BlobStore,
    signal: AbortSignal,
): Promise<void> {
    verifyManifestShape(manifest);
    const expectedLength = ciphertextLength(manifest);
    const iterable = stagedCiphertext(store, stagePrefix, manifest, signal);
    const iterator = iterable[Symbol.asyncIterator]();
    try {
        await abortable(
            () =>
                blobStore.put(
                    manifest.blobId.slice(),
                    expectedLength,
                    { [Symbol.asyncIterator]: (): AsyncIterator<Uint8Array> => iterator },
                    signal,
                ),
            signal,
        );
    } finally {
        await iterator.return?.();
    }

    const head = await abortable(() => blobStore.head(manifest.blobId.slice(), signal), signal);
    if (head === undefined || head.byteLength !== expectedLength) {
        throw new ChatAttachmentAuthenticationError(
            "Blob verification head has an inconsistent length",
        );
    }
    const digest = sha256.create();
    let offset = 0;
    for (let index = 0; index < manifest.chunkCount; index += 1) {
        const length = ciphertextChunkLength(manifest, index);
        const backendRange = await abortable(
            () => blobStore.get(manifest.blobId.slice(), offset, length, signal),
            signal,
        );
        if (!(backendRange instanceof Uint8Array) || backendRange.length !== length) {
            throw new ChatAttachmentAuthenticationError("Blob verification range was truncated");
        }
        const ownedBackendRange = backendRange.slice();
        const staged = await store.get(stageChunkKey(stagePrefix, index));
        try {
            if (
                staged === undefined ||
                staged.length !== length ||
                !equalBytes(ownedBackendRange, staged)
            ) {
                throw new ChatAttachmentAuthenticationError(
                    "Blob verification differs from staged ciphertext",
                );
            }
            digest.update(ownedBackendRange);
        } finally {
            ownedBackendRange.fill(0);
            staged?.fill(0);
        }
        offset += length;
    }
    const observedBlobId = digest.digest();
    try {
        if (offset !== expectedLength || !equalBytes(observedBlobId, manifest.blobId)) {
            throw new ChatAttachmentAuthenticationError("Blob verification digest failed");
        }
    } finally {
        observedBlobId.fill(0);
    }
}

/** Delete a bounded-page durable ciphertext staging prefix. */
export async function clearAttachmentStage(store: MurmurStore, stagePrefix: string): Promise<void> {
    for (;;) {
        const page = await store.scan(stagePrefix, { limit: STAGE_PAGE });
        if (page.size === 0) return;
        await store.transaction(async (transaction) => {
            for (const key of page.keys()) await transaction.delete(key);
        });
    }
}

/** Stream independently authenticated plaintext without mutating backend buffers. */
export async function* openVerifiedAttachment(
    manifest: EncodedManifest,
    conversationId: Uint8Array,
    sender: Uint8Array,
    blobStore: BlobStore,
    signal: AbortSignal,
): AsyncIterable<Uint8Array> {
    verifyManifestShape(manifest);
    validateBindings(conversationId, sender);
    const expectedCommitment = keyCommitment(
        manifest.fileKey,
        manifest.fileId,
        conversationId,
        sender,
        manifest.plaintextLength,
        manifest.chunkCount,
    );
    try {
        if (!equalBytes(expectedCommitment, manifest.commitment)) {
            throw new ChatAttachmentAuthenticationError("Attachment key commitment failed");
        }
    } finally {
        expectedCommitment.fill(0);
    }
    const expectedLength = ciphertextLength(manifest);
    const head = await abortable(() => blobStore.head(manifest.blobId.slice(), signal), signal);
    if (head === undefined || head.byteLength !== expectedLength) {
        throw new ChatAttachmentAuthenticationError("Attachment blob is missing or wrong length");
    }
    const key = deriveContentKey(manifest.fileKey, manifest.fileId);
    const blobDigest = sha256.create();
    let offset = 0;
    try {
        for (let index = 0; index < manifest.chunkCount; index += 1) {
            ensureNotAborted(signal);
            const length = ciphertextChunkLength(manifest, index);
            const backendRange = await abortable(
                () => blobStore.get(manifest.blobId.slice(), offset, length, signal),
                signal,
            );
            if (!(backendRange instanceof Uint8Array) || backendRange.length !== length) {
                throw new ChatAttachmentAuthenticationError("Attachment range was truncated");
            }
            const ciphertext = backendRange.slice();
            blobDigest.update(ciphertext);
            const nonce = chunkNonce(index);
            const aad = chunkAad(
                conversationId,
                sender,
                manifest.fileId,
                manifest.plaintextLength,
                manifest.chunkCount,
                index,
            );
            try {
                let plaintext: Uint8Array;
                try {
                    plaintext = chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
                } catch {
                    throw new ChatAttachmentAuthenticationError(
                        "Attachment chunk authentication failed",
                    );
                }
                yield plaintext;
            } finally {
                ciphertext.fill(0);
                nonce.fill(0);
                aad.fill(0);
            }
            offset += length;
        }
        const observedBlobId = blobDigest.digest();
        try {
            if (offset !== expectedLength || !equalBytes(observedBlobId, manifest.blobId)) {
                throw new ChatAttachmentAuthenticationError("Attachment blob digest failed");
            }
        } finally {
            observedBlobId.fill(0);
        }
    } finally {
        key.fill(0);
    }
}

async function* stagedCiphertext(
    store: MurmurStore,
    stagePrefix: string,
    manifest: EncodedManifest,
    signal: AbortSignal,
): AsyncIterable<Uint8Array> {
    for (let index = 0; index < manifest.chunkCount; index += 1) {
        ensureNotAborted(signal);
        const expected = ciphertextChunkLength(manifest, index);
        const stored = await store.get(stageChunkKey(stagePrefix, index));
        if (stored === undefined || stored.length !== expected) {
            stored?.fill(0);
            throw new ChatAttachmentAuthenticationError("Durable ciphertext stage is incomplete");
        }
        try {
            yield stored;
        } finally {
            stored.fill(0);
        }
    }
}

function deriveContentKey(fileKey: Uint8Array, fileId: Uint8Array): Uint8Array {
    if (fileKey.length !== KEY_BYTES || fileId.length !== FILE_ID_BYTES) {
        throw new ChatAttachmentAuthenticationError("Invalid attachment key capability");
    }
    return hkdf(sha256, fileKey, fileId, KEY_INFO, KEY_BYTES);
}

function keyCommitment(
    fileKey: Uint8Array,
    fileId: Uint8Array,
    conversationId: Uint8Array,
    sender: Uint8Array,
    plaintextLength: number,
    chunkCount: number,
): Uint8Array {
    const input = concatBytes(
        COMMITMENT_DOMAIN,
        VERSION_AND_CIPHER,
        conversationId,
        sender,
        fileId,
        bytesFromU32(ATTACHMENT_CHUNK_BYTES),
        bytesFromU32(chunkCount),
        bytesFromU64(BigInt(plaintextLength)),
        fileKey,
    );
    try {
        return sha256(input);
    } finally {
        input.fill(0);
    }
}

function chunkAad(
    conversationId: Uint8Array,
    sender: Uint8Array,
    fileId: Uint8Array,
    plaintextLength: number,
    chunkCount: number,
    chunkIndex: number,
): Uint8Array {
    return concatBytes(
        AAD_DOMAIN,
        VERSION_AND_CIPHER,
        conversationId,
        sender,
        fileId,
        bytesFromU32(ATTACHMENT_CHUNK_BYTES),
        bytesFromU32(chunkCount),
        bytesFromU64(BigInt(plaintextLength)),
        bytesFromU64(BigInt(chunkIndex)),
    );
}

function chunkNonce(index: number): Uint8Array {
    return concatBytes(new Uint8Array(4), bytesFromU64(BigInt(index)));
}

function plaintextChunkCount(plaintextLength: number): number {
    return Math.max(1, Math.ceil(plaintextLength / ATTACHMENT_CHUNK_BYTES));
}

function plaintextChunkLength(plaintextLength: number, index: number): number {
    return Math.max(
        0,
        Math.min(ATTACHMENT_CHUNK_BYTES, plaintextLength - index * ATTACHMENT_CHUNK_BYTES),
    );
}

function ciphertextChunkLength(manifest: EncodedManifest, index: number): number {
    return plaintextChunkLength(manifest.plaintextLength, index) + TAG_BYTES;
}

function ciphertextLength(manifest: EncodedManifest): number {
    return manifest.plaintextLength + manifest.chunkCount * TAG_BYTES;
}

function stageChunkKey(prefix: string, index: number): string {
    return `${prefix}${index.toString(16).padStart(8, "0")}`;
}

function validateSource(source: AttachmentSource): void {
    if (
        source === null ||
        typeof source !== "object" ||
        typeof source.sourceId !== "string" ||
        source.sourceId.length === 0 ||
        source.sourceId.length > 4096 ||
        !Number.isSafeInteger(source.byteLength) ||
        source.byteLength < 0 ||
        source.byteLength > MAXIMUM_ATTACHMENT_BYTES ||
        typeof source.read !== "function"
    ) {
        throw new ChatAttachmentSourceChangedError("Invalid attachment source");
    }
}

function validateBindings(conversationId: Uint8Array, sender: Uint8Array): void {
    if (
        !(conversationId instanceof Uint8Array) ||
        conversationId.length !== GROUP_ID_BYTES ||
        !(sender instanceof Uint8Array) ||
        sender.length !== IDENTITY_BYTES
    ) {
        throw new ChatAttachmentAuthenticationError("Invalid attachment bindings");
    }
}

async function readOwnedSourceRange(
    source: AttachmentSource,
    offset: number,
    length: number,
    signal: AbortSignal,
): Promise<Uint8Array> {
    const borrowed = await abortable(() => source.read(offset, length, signal), signal);
    if (!(borrowed instanceof Uint8Array) || borrowed.length !== length) {
        throw new ChatAttachmentSourceChangedError("Attachment source returned a changed range");
    }
    return borrowed.slice();
}

async function abortable<Result>(
    operation: () => Promise<Result>,
    signal: AbortSignal,
): Promise<Result> {
    ensureNotAborted(signal);
    let promise: Promise<Result>;
    try {
        promise = Promise.resolve(operation());
    } catch (error: unknown) {
        if (signal.aborted) throw abortError(signal);
        throw error;
    }
    if (signal.aborted) {
        void promise.catch((): undefined => undefined);
        throw abortError(signal);
    }
    let onAbort: (() => void) | undefined;
    const aborted = new Promise<never>((_resolve, reject) => {
        onAbort = (): void => reject(abortError(signal));
        signal.addEventListener("abort", onAbort, { once: true });
    });
    try {
        return await Promise.race([promise, aborted]);
    } finally {
        if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
    }
}

/** Strictly validate every manifest field before any cryptographic use. */
export function verifyManifestShape(manifest: unknown): asserts manifest is EncodedManifest {
    if (manifest === null || typeof manifest !== "object") {
        throw new ChatAttachmentAuthenticationError("Invalid attachment manifest");
    }
    const candidate = manifest as Readonly<Record<string, unknown>>;
    if (
        !(candidate.metadata instanceof Uint8Array) ||
        candidate.metadata.length > MAXIMUM_FRAME_BYTES ||
        !(candidate.fileId instanceof Uint8Array) ||
        candidate.fileId.length !== FILE_ID_BYTES ||
        !(candidate.fileKey instanceof Uint8Array) ||
        candidate.fileKey.length !== KEY_BYTES ||
        !(candidate.commitment instanceof Uint8Array) ||
        candidate.commitment.length !== HASH_BYTES ||
        !(candidate.blobId instanceof Uint8Array) ||
        candidate.blobId.length !== HASH_BYTES ||
        !Number.isSafeInteger(candidate.plaintextLength) ||
        (candidate.plaintextLength as number) < 0 ||
        (candidate.plaintextLength as number) > MAXIMUM_ATTACHMENT_BYTES ||
        candidate.chunkSize !== ATTACHMENT_CHUNK_BYTES ||
        !Number.isSafeInteger(candidate.chunkCount) ||
        (candidate.chunkCount as number) < 1 ||
        (candidate.chunkCount as number) > 0xffff_ffff ||
        candidate.chunkCount !== plaintextChunkCount(candidate.plaintextLength as number)
    ) {
        throw new ChatAttachmentAuthenticationError("Invalid attachment manifest");
    }
}
