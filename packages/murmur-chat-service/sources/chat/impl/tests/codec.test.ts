import { describe, expect, it } from "vitest";
import {
    ATTACHMENT_CHUNK_BYTES,
    decodeFrame,
    decodeOutbox,
    encodeFrame,
    encodeOutbox,
    type OutboxRecord,
} from "../codec.js";

describe("strict chat codecs", () => {
    const frame = (): Uint8Array =>
        encodeFrame({
            messageId: new Uint8Array(16).fill(1),
            claimedAt: 42,
            body: new Uint8Array([1, 2, 3]),
            attachments: [
                {
                    fileId: new Uint8Array(16).fill(2),
                    fileKey: new Uint8Array(32).fill(3),
                    commitment: new Uint8Array(32).fill(4),
                    blobId: new Uint8Array(32).fill(5),
                    plaintextLength: 300_000,
                    chunkSize: ATTACHMENT_CHUNK_BYTES,
                    chunkCount: 2,
                    metadata: new Uint8Array([6]),
                },
            ],
        });

    it("roundtrips and rejects versions, truncation, trailing bytes, and inconsistent counts", () => {
        expect(decodeFrame(frame()).body).toEqual(new Uint8Array([1, 2, 3]));

        const version = frame();
        version[3] = 2;
        expect(() => decodeFrame(version)).toThrow();

        const valid = frame();
        expect(() => decodeFrame(valid.slice(0, -1))).toThrow();
        const trailing = new Uint8Array(valid.length + 1);
        trailing.set(valid);
        expect(() => decodeFrame(trailing)).toThrow();

        const inconsistent = frame();
        const countOffset = 4 + 16 + 8 + 4 + 3 + 1 + 16 + 32 + 32 + 32 + 4 + 4;
        new DataView(inconsistent.buffer).setUint32(countOffset, 1);
        expect(() => decodeFrame(inconsistent)).toThrow(/Inconsistent/);
    });

    it("roundtrips strict durable outbox records and fails corruption closed", () => {
        const record: OutboxRecord = {
            status: "preparing",
            enqueueSequence: 1n,
            conversationId: new Uint8Array(32).fill(1),
            messageId: new Uint8Array(16).fill(2),
            claimedAt: 100,
            body: new Uint8Array([3]),
            attachments: [
                {
                    stageState: "new",
                    sourceId: "stable",
                    metadata: new Uint8Array([4]),
                    fileId: new Uint8Array(16).fill(5),
                    fileKey: new Uint8Array(32).fill(6),
                    sourceHash: new Uint8Array(32).fill(7),
                    plaintextLength: 1,
                },
            ],
        };
        expect(decodeOutbox(encodeOutbox(record)).attachments[0]?.sourceId).toBe("stable");
        const corrupt = encodeOutbox(record);
        corrupt[3] = 9;
        expect(() => decodeOutbox(corrupt)).toThrow(/Corrupt chat outbox/);

        const failed = decodeOutbox(
            encodeOutbox({
                ...record,
                status: "failed",
                lastError: { code: "source-changed", message: "source changed" },
            }),
        );
        expect(failed.lastError).toEqual({
            code: "source-changed",
            message: "source changed",
        });
    });

    it("keeps claimedAt encode/decode bounds consistent", () => {
        expect(() =>
            encodeFrame({
                messageId: new Uint8Array(16),
                claimedAt: Number.MAX_SAFE_INTEGER + 1,
                body: new Uint8Array(),
                attachments: [],
            }),
        ).toThrow(/u64/);
        expect(() =>
            encodeFrame({
                messageId: new Uint8Array(16),
                claimedAt: 1.5,
                body: new Uint8Array(),
                attachments: [],
            }),
        ).toThrow(/u64/);
    });
});
