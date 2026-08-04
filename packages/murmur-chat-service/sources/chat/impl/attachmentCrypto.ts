import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
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
    HASH_BYTES,
    IDENTITY_BYTES,
    type EncodedAttachmentIntent,
    type EncodedManifest,
    GROUP_ID_BYTES,
    TAG_BYTES,
} from "./codec.js";

const KEY_INFO = new TextEncoder().encode("murmur/chat/attachment/content-key/v1");
const AAD_DOMAIN = new TextEncoder().encode("murmur/chat/attachment/chunk/v1");
const COMMITMENT_DOMAIN = new TextEncoder().encode("murmur/chat/attachment/commitment/v1");
const VERSION_AND_CIPHER = new Uint8Array([1, 1]);

export async function hashAttachmentSource(
    source: AttachmentSource,
    signal: AbortSignal,
): Promise<Uint8Array> {
    validateSource(source);
    const hash = sha256.create();
    for (let offset = 0; offset < source.byteLength; offset += ATTACHMENT_CHUNK_BYTES) {
        ensureNotAborted(signal);
        const length = Math.min(ATTACHMENT_CHUNK_BYTES, source.byteLength - offset);
        const part = await abortable(source.read(offset, length, signal), signal);
        if (!(part instanceof Uint8Array) || part.length !== length) {
            part?.fill(0);
            throw new ChatAttachmentSourceChangedError("Attachment source returned a short range");
        }
        hash.update(part);
        part.fill(0);
    }
    return hash.digest();
}

export async function prepareAndUploadAttachment(
    intent: EncodedAttachmentIntent,
    conversationId: Uint8Array,
    sender: Uint8Array,
    resolve: (sourceId: string, signal: AbortSignal) => Promise<AttachmentSource>,
    blobStore: BlobStore,
    signal: AbortSignal,
): Promise<EncodedManifest> {
    const source = await abortable(resolve(intent.sourceId, signal), signal);
    validateSource(source);
    if (source.sourceId !== intent.sourceId || source.byteLength !== intent.plaintextLength) {
        throw new ChatAttachmentSourceChangedError("Attachment source identity or length changed");
    }
    const currentHash = await hashAttachmentSource(source, signal);
    try {
        if (!equalBytes(currentHash, intent.sourceHash)) {
            throw new ChatAttachmentSourceChangedError("Attachment source bytes changed");
        }
    } finally {
        currentHash.fill(0);
    }

    const chunkCount =
        source.byteLength === 0 ? 0 : Math.ceil(source.byteLength / ATTACHMENT_CHUNK_BYTES);
    const ciphertextLength = source.byteLength + chunkCount * TAG_BYTES;
    const digest = sha256.create();
    for await (const chunk of encryptedChunks(
        source,
        intent.fileKey,
        intent.fileId,
        conversationId,
        sender,
        chunkCount,
        signal,
    )) {
        digest.update(chunk);
        chunk.fill(0);
    }
    const blobId = digest.digest();
    const commitment = keyCommitment(
        intent.fileKey,
        intent.fileId,
        conversationId,
        sender,
        source.byteLength,
        chunkCount,
    );
    const head = await abortable(blobStore.head(blobId, signal), signal);
    if (head !== undefined && head.byteLength !== ciphertextLength) {
        blobId.fill(0);
        commitment.fill(0);
        throw new ChatAttachmentAuthenticationError("Blob head has an inconsistent length");
    }
    if (head === undefined) {
        await abortable(
            blobStore.put(
                blobId,
                ciphertextLength,
                encryptedChunks(
                    source,
                    intent.fileKey,
                    intent.fileId,
                    conversationId,
                    sender,
                    chunkCount,
                    signal,
                ),
                signal,
            ),
            signal,
        );
    }
    return {
        metadata: intent.metadata.slice(),
        fileId: intent.fileId.slice(),
        fileKey: intent.fileKey.slice(),
        commitment,
        blobId,
        plaintextLength: source.byteLength,
        chunkSize: ATTACHMENT_CHUNK_BYTES,
        chunkCount,
    };
}

export async function* openVerifiedAttachment(
    manifest: EncodedManifest,
    conversationId: Uint8Array,
    sender: Uint8Array,
    blobStore: BlobStore,
    signal: AbortSignal,
): AsyncIterable<Uint8Array> {
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
    const expectedLength = manifest.plaintextLength + manifest.chunkCount * TAG_BYTES;
    const head = await abortable(blobStore.head(manifest.blobId, signal), signal);
    if (head === undefined || head.byteLength !== expectedLength) {
        throw new ChatAttachmentAuthenticationError("Attachment blob is missing or wrong length");
    }
    const key = deriveContentKey(manifest.fileKey, manifest.fileId);
    const blobDigest = sha256.create();
    let ciphertextOffset = 0;
    try {
        for (let index = 0; index < manifest.chunkCount; index += 1) {
            ensureNotAborted(signal);
            const plaintextLength = Math.min(
                ATTACHMENT_CHUNK_BYTES,
                manifest.plaintextLength - index * ATTACHMENT_CHUNK_BYTES,
            );
            const ciphertextLength = plaintextLength + TAG_BYTES;
            const ciphertext = await abortable(
                blobStore.get(manifest.blobId, ciphertextOffset, ciphertextLength, signal),
                signal,
            );
            if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ciphertextLength) {
                ciphertext?.fill(0);
                throw new ChatAttachmentAuthenticationError("Attachment range was truncated");
            }
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
            ciphertextOffset += ciphertextLength;
        }
        if (
            ciphertextOffset !== expectedLength ||
            !equalBytes(blobDigest.digest(), manifest.blobId)
        ) {
            throw new ChatAttachmentAuthenticationError("Attachment blob digest failed");
        }
    } finally {
        key.fill(0);
    }
}

async function* encryptedChunks(
    source: AttachmentSource,
    fileKey: Uint8Array,
    fileId: Uint8Array,
    conversationId: Uint8Array,
    sender: Uint8Array,
    chunkCount: number,
    signal: AbortSignal,
): AsyncIterable<Uint8Array> {
    validateBindings(conversationId, sender);
    const key = deriveContentKey(fileKey, fileId);
    try {
        for (let index = 0; index < chunkCount; index += 1) {
            ensureNotAborted(signal);
            const offset = index * ATTACHMENT_CHUNK_BYTES;
            const length = Math.min(ATTACHMENT_CHUNK_BYTES, source.byteLength - offset);
            const plaintext = await abortable(source.read(offset, length, signal), signal);
            if (!(plaintext instanceof Uint8Array) || plaintext.length !== length) {
                plaintext?.fill(0);
                throw new ChatAttachmentSourceChangedError(
                    "Attachment source returned a changed range",
                );
            }
            const nonce = chunkNonce(index);
            const aad = chunkAad(
                conversationId,
                sender,
                fileId,
                source.byteLength,
                chunkCount,
                index,
            );
            try {
                yield chacha20poly1305(key, nonce, aad).encrypt(plaintext);
            } finally {
                plaintext.fill(0);
                nonce.fill(0);
                aad.fill(0);
            }
        }
    } finally {
        key.fill(0);
    }
}

function deriveContentKey(fileKey: Uint8Array, fileId: Uint8Array): Uint8Array {
    if (fileKey.length !== 32 || fileId.length !== 16) {
        throw new ChatAttachmentAuthenticationError("Invalid attachment key capability");
    }
    return hkdf(sha256, fileKey, fileId, KEY_INFO, 32);
}

function keyCommitment(
    fileKey: Uint8Array,
    fileId: Uint8Array,
    conversationId: Uint8Array,
    sender: Uint8Array,
    plaintextLength: number,
    chunkCount: number,
): Uint8Array {
    return sha256(
        concatBytes(
            COMMITMENT_DOMAIN,
            VERSION_AND_CIPHER,
            conversationId,
            sender,
            fileId,
            bytesFromU32(ATTACHMENT_CHUNK_BYTES),
            bytesFromU32(chunkCount),
            bytesFromU64(BigInt(plaintextLength)),
            fileKey,
        ),
    );
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

function validateSource(source: AttachmentSource): void {
    if (
        typeof source.sourceId !== "string" ||
        source.sourceId.length === 0 ||
        source.sourceId.length > 4096 ||
        !Number.isSafeInteger(source.byteLength) ||
        source.byteLength < 0 ||
        source.byteLength > 100 * 1024 * 1024
    ) {
        throw new ChatAttachmentSourceChangedError("Invalid attachment source");
    }
}

function validateBindings(conversationId: Uint8Array, sender: Uint8Array): void {
    if (
        conversationId.length !== GROUP_ID_BYTES ||
        sender.length !== IDENTITY_BYTES ||
        !(conversationId instanceof Uint8Array) ||
        !(sender instanceof Uint8Array)
    ) {
        throw new ChatAttachmentAuthenticationError("Invalid attachment bindings");
    }
}

async function abortable<Result>(promise: Promise<Result>, signal: AbortSignal): Promise<Result> {
    ensureNotAborted(signal);
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

export function verifyManifestShape(manifest: EncodedManifest): void {
    if (
        manifest.commitment.length !== HASH_BYTES ||
        manifest.blobId.length !== HASH_BYTES ||
        manifest.chunkCount !==
            (manifest.plaintextLength === 0
                ? 0
                : Math.ceil(manifest.plaintextLength / ATTACHMENT_CHUNK_BYTES))
    ) {
        throw new ChatAttachmentAuthenticationError("Invalid attachment manifest");
    }
}
