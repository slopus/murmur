import { randomBytes } from "@noble/hashes/utils";
import { describe, expect, it } from "vitest";
import { ChatAttachmentSourceChangedError } from "../../errors.js";
import type { AttachmentSource, BlobHead, BlobStore } from "../../types.js";
import { openVerifiedAttachment, prepareAndUploadAttachment } from "../attachmentCrypto.js";
import { concatBytes } from "../bytes.js";
import type { EncodedAttachmentIntent } from "../codec.js";
import { MemoryBlobStore } from "../memoryBlobStore.js";
import { sha256 } from "@noble/hashes/sha256";

class MutableSource implements AttachmentSource {
    readonly sourceId: string;
    bytes: Uint8Array;

    constructor(sourceId: string, bytes: Uint8Array) {
        this.sourceId = sourceId;
        this.bytes = bytes;
    }

    get byteLength(): number {
        return this.bytes.length;
    }

    async read(offset: number, byteLength: number, signal: AbortSignal): Promise<Uint8Array> {
        if (signal.aborted) throw signal.reason;
        return this.bytes.slice(offset, offset + byteLength);
    }
}

function intent(source: MutableSource): EncodedAttachmentIntent {
    return {
        sourceId: source.sourceId,
        metadata: new Uint8Array([9]),
        fileId: randomBytes(16),
        fileKey: randomBytes(32),
        sourceHash: sha256(source.bytes),
        plaintextLength: source.byteLength,
    };
}

async function collect(values: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    for await (const value of values) parts.push(value);
    return concatBytes(...parts);
}

class RecordingBlobStore implements BlobStore {
    readonly inner = new MemoryBlobStore();
    uploaded: Uint8Array = new Uint8Array();

    async put(
        blobId: Uint8Array,
        byteLength: number,
        bytes: AsyncIterable<Uint8Array>,
        signal: AbortSignal,
    ): Promise<void> {
        this.uploaded = await collect(bytes);
        const uploaded = this.uploaded;
        await this.inner.put(
            blobId,
            byteLength,
            (async function* (): AsyncIterable<Uint8Array> {
                yield uploaded;
            })(),
            signal,
        );
    }

    head(blobId: Uint8Array, signal: AbortSignal): Promise<BlobHead | undefined> {
        return this.inner.head(blobId, signal);
    }

    get(
        blobId: Uint8Array,
        offset: number,
        byteLength: number,
        signal: AbortSignal,
    ): Promise<Uint8Array> {
        return this.inner.get(blobId, offset, byteLength, signal);
    }
}

describe("attachment cryptography", () => {
    const conversation = new Uint8Array(32).fill(1);
    const sender = new Uint8Array(32).fill(2);

    it("stores ciphertext only and streams an authenticated roundtrip", async () => {
        const plaintext = new TextEncoder().encode("private attachment bytes");
        const source = new MutableSource("one", plaintext);
        const blobs = new RecordingBlobStore();
        const capability = await prepareAndUploadAttachment(
            intent(source),
            conversation,
            sender,
            async () => source,
            blobs,
            new AbortController().signal,
        );
        expect(blobs.uploaded).not.toEqual(plaintext);
        expect(new TextDecoder().decode(blobs.uploaded)).not.toContain("private attachment");
        expect(
            await collect(
                openVerifiedAttachment(
                    capability,
                    conversation,
                    sender,
                    blobs,
                    new AbortController().signal,
                ),
            ),
        ).toEqual(plaintext);
    });

    it("regenerates byte-identical ciphertext and rejects changed sources first", async () => {
        const source = new MutableSource("retry", new Uint8Array(300_000).fill(11));
        const stableIntent = intent(source);
        const first = new RecordingBlobStore();
        const firstManifest = await prepareAndUploadAttachment(
            stableIntent,
            conversation,
            sender,
            async () => source,
            first,
            new AbortController().signal,
        );
        const second = new RecordingBlobStore();
        const secondManifest = await prepareAndUploadAttachment(
            stableIntent,
            conversation,
            sender,
            async () => source,
            second,
            new AbortController().signal,
        );
        expect(second.uploaded).toEqual(first.uploaded);
        expect(secondManifest.blobId).toEqual(firstManifest.blobId);

        source.bytes[0]! ^= 1;
        await expect(
            prepareAndUploadAttachment(
                stableIntent,
                conversation,
                sender,
                async () => source,
                new MemoryBlobStore(),
                new AbortController().signal,
            ),
        ).rejects.toBeInstanceOf(ChatAttachmentSourceChangedError);
    });

    it("recovers an ambiguous completed upload without changing ciphertext", async () => {
        const source = new MutableSource("ambiguous", new Uint8Array(80_000).fill(13));
        const stableIntent = intent(source);
        const inner = new RecordingBlobStore();
        let puts = 0;
        const ambiguous: BlobStore = {
            put: async (blobId, byteLength, bytes, signal) => {
                puts += 1;
                await inner.put(blobId, byteLength, bytes, signal);
                throw new Error("response lost after durable put");
            },
            head: inner.head.bind(inner),
            get: inner.get.bind(inner),
        };
        await expect(
            prepareAndUploadAttachment(
                stableIntent,
                conversation,
                sender,
                async () => source,
                ambiguous,
                new AbortController().signal,
            ),
        ).rejects.toThrow("response lost");
        const uploaded = inner.uploaded.slice();
        const recovered = await prepareAndUploadAttachment(
            stableIntent,
            conversation,
            sender,
            async () => source,
            ambiguous,
            new AbortController().signal,
        );
        expect(puts).toBe(1);
        expect(recovered.blobId).toEqual(sha256(uploaded));
    });

    it("uses random capabilities so identical plaintext has different blob IDs", async () => {
        const source = new MutableSource("same", new Uint8Array(10_000).fill(7));
        const blobs = new MemoryBlobStore();
        const first = await prepareAndUploadAttachment(
            intent(source),
            conversation,
            sender,
            async () => source,
            blobs,
            new AbortController().signal,
        );
        const second = await prepareAndUploadAttachment(
            intent(source),
            conversation,
            sender,
            async () => source,
            blobs,
            new AbortController().signal,
        );
        expect(second.blobId).not.toEqual(first.blobId);
    });

    it("rejects cross-group and cross-sender manifest replay", async () => {
        const source = new MutableSource("bound", randomBytes(30));
        const blobs = new MemoryBlobStore();
        const manifest = await prepareAndUploadAttachment(
            intent(source),
            conversation,
            sender,
            async () => source,
            blobs,
            new AbortController().signal,
        );
        await expect(
            collect(
                openVerifiedAttachment(
                    manifest,
                    new Uint8Array(32).fill(3),
                    sender,
                    blobs,
                    new AbortController().signal,
                ),
            ),
        ).rejects.toThrow(/commitment/);
        await expect(
            collect(
                openVerifiedAttachment(
                    manifest,
                    conversation,
                    new Uint8Array(32).fill(4),
                    blobs,
                    new AbortController().signal,
                ),
            ),
        ).rejects.toThrow(/commitment/);
    });

    it("rejects corruption, truncation, extension, reordering, and aborts stalls", async () => {
        const source = new MutableSource("hostile", new Uint8Array(300_000).fill(12));
        const base = new MemoryBlobStore();
        const manifest = await prepareAndUploadAttachment(
            intent(source),
            conversation,
            sender,
            async () => source,
            base,
            new AbortController().signal,
        );
        const corrupt: BlobStore = {
            put: base.put.bind(base),
            head: base.head.bind(base),
            get: async (id, offset, length, signal) => {
                const bytes = await base.get(id, offset, length, signal);
                bytes[0]! ^= 1;
                return bytes;
            },
        };
        await expect(
            collect(
                openVerifiedAttachment(
                    manifest,
                    conversation,
                    sender,
                    corrupt,
                    new AbortController().signal,
                ),
            ),
        ).rejects.toThrow(/authentication/);

        for (const delta of [-1, 1]) {
            const wrongLength: BlobStore = {
                put: base.put.bind(base),
                head: async () => ({
                    byteLength: manifest.plaintextLength + manifest.chunkCount * 16 + delta,
                }),
                get: base.get.bind(base),
            };
            await expect(
                collect(
                    openVerifiedAttachment(
                        manifest,
                        conversation,
                        sender,
                        wrongLength,
                        new AbortController().signal,
                    ),
                ),
            ).rejects.toThrow(/wrong length/);
        }

        const reordered: BlobStore = {
            put: base.put.bind(base),
            head: base.head.bind(base),
            get: async (id, offset, length, signal) =>
                base.get(id, offset === 0 ? 256 * 1024 + 16 : 0, length, signal),
        };
        await expect(
            collect(
                openVerifiedAttachment(
                    manifest,
                    conversation,
                    sender,
                    reordered,
                    new AbortController().signal,
                ),
            ),
        ).rejects.toThrow();

        const controller = new AbortController();
        const stalled: BlobStore = {
            put: base.put.bind(base),
            head: async () => new Promise<BlobHead>(() => undefined),
            get: base.get.bind(base),
        };
        const pending = collect(
            openVerifiedAttachment(manifest, conversation, sender, stalled, controller.signal),
        );
        controller.abort(new Error("stop"));
        await expect(pending).rejects.toThrow("stop");
    });
});
