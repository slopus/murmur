import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { MemoryMurmurStore } from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import { ChatAttachmentSourceChangedError } from "../../errors.js";
import type { AttachmentSource, BlobHead, BlobStore } from "../../types.js";
import {
    openVerifiedAttachment,
    stageAttachment,
    uploadStagedAttachment,
    verifyManifestShape,
} from "../attachmentCrypto.js";
import { concatBytes } from "../bytes.js";
import type { EncodedAttachmentIntent, EncodedManifest } from "../codec.js";
import { MemoryBlobStore } from "../memoryBlobStore.js";

class MutableSource implements AttachmentSource {
    readonly sourceId: string;
    bytes: Uint8Array;
    reads = 0;
    mutateAfterFirstRead = false;

    constructor(sourceId: string, bytes: Uint8Array) {
        this.sourceId = sourceId;
        this.bytes = bytes;
    }

    get byteLength(): number {
        return this.bytes.length;
    }

    async read(offset: number, byteLength: number, signal: AbortSignal): Promise<Uint8Array> {
        if (signal.aborted) throw signal.reason;
        this.reads += 1;
        const result = this.bytes.subarray(offset, offset + byteLength);
        if (this.mutateAfterFirstRead && this.reads === 1 && this.bytes.length > byteLength) {
            this.bytes[byteLength]! ^= 1;
        }
        return result;
    }
}

function intent(source: MutableSource): EncodedAttachmentIntent {
    return {
        stageState: "new",
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
    for await (const value of values) parts.push(value.slice());
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

async function stageAndUpload(
    source: MutableSource,
    attachmentIntent: EncodedAttachmentIntent,
    blobs: BlobStore,
    prefix: string = "chat/v1/staging/test/",
): Promise<{ manifest: EncodedManifest; store: MemoryMurmurStore }> {
    const store = new MemoryMurmurStore();
    const conversation = new Uint8Array(32).fill(1);
    const sender = new Uint8Array(32).fill(2);
    const signal = new AbortController().signal;
    const manifest = await stageAttachment(
        source,
        attachmentIntent,
        conversation,
        sender,
        store,
        prefix,
        signal,
    );
    await uploadStagedAttachment(manifest, store, prefix, blobs, signal);
    return { manifest, store };
}

describe("staged attachment cryptography", () => {
    const conversation = new Uint8Array(32).fill(1);
    const sender = new Uint8Array(32).fill(2);

    it("encrypts once into staging, stores ciphertext, and verifies roundtrip", async () => {
        const plaintext = new Uint8Array(300_000).fill(7);
        const source = new MutableSource("one", plaintext);
        const blobs = new RecordingBlobStore();
        const { manifest } = await stageAndUpload(source, intent(source), blobs);
        expect(source.reads).toBe(2);
        expect(blobs.uploaded).not.toEqual(plaintext);
        expect(
            await collect(
                openVerifiedAttachment(
                    manifest,
                    conversation,
                    sender,
                    blobs,
                    new AbortController().signal,
                ),
            ),
        ).toEqual(plaintext);
    });

    it("retries an ambiguous completed PUT from exact staged bytes", async () => {
        const source = new MutableSource("ambiguous", new Uint8Array(80_000).fill(13));
        const stableIntent = intent(source);
        const store = new MemoryMurmurStore();
        const prefix = "chat/v1/staging/ambiguous/";
        const signal = new AbortController().signal;
        const manifest = await stageAttachment(
            source,
            stableIntent,
            conversation,
            sender,
            store,
            prefix,
            signal,
        );
        const recording = new RecordingBlobStore();
        let calls = 0;
        const ambiguous: BlobStore = {
            put: async (blobId, byteLength, bytes, operationSignal) => {
                calls += 1;
                await recording.put(blobId, byteLength, bytes, operationSignal);
                if (calls === 1) throw new Error("response lost");
            },
            head: recording.head.bind(recording),
            get: recording.get.bind(recording),
        };
        await expect(
            uploadStagedAttachment(manifest, store, prefix, ambiguous, signal),
        ).rejects.toThrow("response lost");
        const first = recording.uploaded.slice();
        await uploadStagedAttachment(manifest, store, prefix, ambiguous, signal);
        expect(recording.uploaded).toEqual(first);
        expect(manifest.blobId).toEqual(sha256(first));
    });

    it("detects mutation during the single encryption pass", async () => {
        const original = new Uint8Array(300_000).fill(8);
        const source = new MutableSource("mutating", original.slice());
        const stableIntent = intent(source);
        source.mutateAfterFirstRead = true;
        await expect(
            stageAttachment(
                source,
                stableIntent,
                conversation,
                sender,
                new MemoryMurmurStore(),
                "chat/v1/staging/mutating/",
                new AbortController().signal,
            ),
        ).rejects.toBeInstanceOf(ChatAttachmentSourceChangedError);
    });

    it("never mutates source-owned or backend-owned range buffers", async () => {
        const source = new MutableSource("ownership", new Uint8Array(20).fill(5));
        const originalSource = source.bytes.slice();
        const base = new RecordingBlobStore();
        const { manifest } = await stageAndUpload(source, intent(source), base);
        expect(source.bytes).toEqual(originalSource);
        const sharedBackendBuffer = base.uploaded.slice();
        const hostileOwnership: BlobStore = {
            put: base.put.bind(base),
            head: async () => ({ byteLength: sharedBackendBuffer.length }),
            get: async (_id, offset, length) =>
                sharedBackendBuffer.subarray(offset, offset + length),
        };
        await collect(
            openVerifiedAttachment(
                manifest,
                conversation,
                sender,
                hostileOwnership,
                new AbortController().signal,
            ),
        );
        expect(sharedBackendBuffer).toEqual(base.uploaded);
    });

    it("gives empty files an authenticated unlinkable 16-byte ciphertext", async () => {
        const source = new MutableSource("empty", new Uint8Array());
        const firstBlob = new RecordingBlobStore();
        const secondBlob = new RecordingBlobStore();
        const first = await stageAndUpload(
            source,
            intent(source),
            firstBlob,
            "chat/v1/staging/e1/",
        );
        const second = await stageAndUpload(
            source,
            intent(source),
            secondBlob,
            "chat/v1/staging/e2/",
        );
        expect(firstBlob.uploaded).toHaveLength(16);
        expect(secondBlob.uploaded).toHaveLength(16);
        expect(first.manifest.blobId).not.toEqual(second.manifest.blobId);
    });

    it("strictly rejects malformed manifest shapes before cryptography", () => {
        const malformed: Readonly<Record<string, unknown>> = {
            metadata: new Uint8Array(),
            fileId: new Uint8Array(15),
            fileKey: new Uint8Array(32),
            commitment: new Uint8Array(32),
            blobId: new Uint8Array(32),
            plaintextLength: 0,
            chunkSize: 256 * 1024,
            chunkCount: 0,
        };
        expect(() => verifyManifestShape(malformed)).toThrow(/Invalid attachment manifest/);
        expect(() => verifyManifestShape(null)).toThrow(/Invalid attachment manifest/);
    });
});
