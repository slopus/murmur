import { ChatCodecError, ChatStoreCorruptionError } from "../errors.js";

export const CHAT_PREFIX = "chat/v1/";
export const MAXIMUM_FRAME_BYTES = 256 * 1024;
export const MAXIMUM_ATTACHMENT_BYTES = 100 * 1024 * 1024;
export const ATTACHMENT_CHUNK_BYTES = 256 * 1024;
export const MAXIMUM_ATTACHMENTS = 8;
export const IDENTITY_BYTES = 32;
export const GROUP_ID_BYTES = 32;
export const MESSAGE_ID_BYTES = 16;
export const FILE_ID_BYTES = 16;
export const KEY_BYTES = 32;
export const HASH_BYTES = 32;
export const TAG_BYTES = 16;
export const MAXIMUM_ERROR_BYTES = 1024;
export const MAXIMUM_METADATA_BYTES = MAXIMUM_FRAME_BYTES;

const DESCRIPTOR = new Uint8Array([0x4d, 0x55, 0x52, 0x4d, 0x43, 0x48, 0x41, 0x54, 1]);
const FRAME_MAGIC = new Uint8Array([0x4d, 0x43, 0x48, 1]);
const OUTBOX_MAGIC = new Uint8Array([0x4d, 0x43, 0x4f, 2]);
const PROJECTION_MAGIC = new Uint8Array([0x4d, 0x43, 0x50, 1]);
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export interface EncodedAttachmentIntent {
    stageState: "new" | "staging" | "staged" | "uploaded";
    sourceId: string;
    metadata: Uint8Array;
    fileId: Uint8Array;
    fileKey: Uint8Array;
    sourceHash: Uint8Array;
    plaintextLength: number;
    manifest?: EncodedManifest;
}

export interface OutboxRecord {
    status: "preparing" | "ready" | "handed-off" | "failed";
    enqueueSequence: bigint;
    conversationId: Uint8Array;
    messageId: Uint8Array;
    claimedAt: number;
    body: Uint8Array;
    attachments: EncodedAttachmentIntent[];
    frameDigest?: Uint8Array;
    lastError?: { code: string; message: string };
}

export interface EncodedManifest {
    metadata: Uint8Array;
    fileId: Uint8Array;
    fileKey: Uint8Array;
    commitment: Uint8Array;
    blobId: Uint8Array;
    plaintextLength: number;
    chunkSize: number;
    chunkCount: number;
}

export interface DecodedFrame {
    messageId: Uint8Array;
    claimedAt: number;
    body: Uint8Array;
    attachments: EncodedManifest[];
}

class Writer {
    readonly #parts: Uint8Array[] = [];
    #length = 0;

    bytes(value: Uint8Array, expected?: number): void {
        if (
            !(value instanceof Uint8Array) ||
            (expected !== undefined && value.length !== expected)
        ) {
            throw new ChatCodecError("Invalid fixed-length byte field");
        }
        this.#parts.push(value);
        this.#length += value.length;
    }

    u8(value: number): void {
        this.number(value, 1);
    }

    u16(value: number): void {
        this.number(value, 2);
    }

    u32(value: number): void {
        this.number(value, 4);
    }

    u64(value: number | bigint): void {
        if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) {
            throw new ChatCodecError("Invalid u64 number");
        }
        const integer = typeof value === "number" ? BigInt(value) : value;
        if (integer < 0n || integer > 0xffff_ffff_ffff_ffffn) {
            throw new ChatCodecError("Integer is outside u64");
        }
        const bytes = new Uint8Array(8);
        new DataView(bytes.buffer).setBigUint64(0, integer);
        this.bytes(bytes);
    }

    variable16(value: Uint8Array): void {
        if (value.length > 0xffff) {
            throw new ChatCodecError("Field exceeds u16 bound");
        }
        this.u16(value.length);
        this.bytes(value);
    }

    variable32(value: Uint8Array): void {
        this.u32(value.length);
        this.bytes(value);
    }

    finish(maximum: number): Uint8Array {
        if (this.#length > maximum) {
            throw new ChatCodecError(`Encoded value exceeds ${maximum} bytes`);
        }
        const result = new Uint8Array(this.#length);
        let offset = 0;
        for (const part of this.#parts) {
            result.set(part, offset);
            offset += part.length;
        }
        return result;
    }

    private number(value: number, bytes: 1 | 2 | 4): void {
        const maximum = bytes === 1 ? 0xff : bytes === 2 ? 0xffff : 0xffff_ffff;
        if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
            throw new ChatCodecError("Invalid unsigned integer");
        }
        const encoded = new Uint8Array(bytes);
        const view = new DataView(encoded.buffer);
        if (bytes === 1) view.setUint8(0, value);
        else if (bytes === 2) view.setUint16(0, value);
        else view.setUint32(0, value);
        this.bytes(encoded);
    }
}

class Reader {
    readonly #bytes: Uint8Array;
    #offset = 0;

    constructor(bytes: Uint8Array, maximum: number) {
        if (!(bytes instanceof Uint8Array) || bytes.length > maximum) {
            throw new ChatCodecError("Invalid or oversized binary value");
        }
        this.#bytes = bytes;
    }

    bytes(length: number): Uint8Array {
        if (!Number.isSafeInteger(length) || length < 0 || length > this.remaining) {
            throw new ChatCodecError("Truncated binary value");
        }
        const result = this.#bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    u8(): number {
        return this.number(1);
    }

    u16(): number {
        return this.number(2);
    }

    u32(): number {
        return this.number(4);
    }

    u64Number(): number {
        const value = new DataView(this.bytes(8).buffer).getBigUint64(0);
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new ChatCodecError("u64 does not fit a safe number");
        }
        return Number(value);
    }

    u64Bigint(): bigint {
        return new DataView(this.bytes(8).buffer).getBigUint64(0);
    }

    variable16(maximum: number): Uint8Array {
        const length = this.u16();
        if (length > maximum) throw new ChatCodecError("u16 field exceeds bound");
        return this.bytes(length);
    }

    variable32(maximum: number): Uint8Array {
        const length = this.u32();
        if (length > maximum) throw new ChatCodecError("u32 field exceeds bound");
        return this.bytes(length);
    }

    expect(expected: Uint8Array): void {
        const actual = this.bytes(expected.length);
        let different = 0;
        for (let index = 0; index < expected.length; index += 1) {
            different |= actual[index]! ^ expected[index]!;
        }
        if (different !== 0) throw new ChatCodecError("Unknown binary version or domain");
    }

    end(): void {
        if (this.remaining !== 0) throw new ChatCodecError("Trailing binary bytes");
    }

    get remaining(): number {
        return this.#bytes.length - this.#offset;
    }

    private number(bytes: 1 | 2 | 4): number {
        const view = new DataView(this.bytes(bytes).buffer);
        if (bytes === 1) return view.getUint8(0);
        if (bytes === 2) return view.getUint16(0);
        return view.getUint32(0);
    }
}

export function chatDescriptor(): Uint8Array {
    return DESCRIPTOR.slice();
}

export function isChatDescriptor(value: Uint8Array): boolean {
    if (value.length !== DESCRIPTOR.length) return false;
    let different = 0;
    for (let index = 0; index < value.length; index += 1) {
        different |= value[index]! ^ DESCRIPTOR[index]!;
    }
    return different === 0;
}

function writeManifest(writer: Writer, manifest: EncodedManifest): void {
    writer.bytes(manifest.fileId, FILE_ID_BYTES);
    writer.bytes(manifest.fileKey, KEY_BYTES);
    writer.bytes(manifest.commitment, HASH_BYTES);
    writer.bytes(manifest.blobId, HASH_BYTES);
    writer.u32(manifest.plaintextLength);
    writer.u32(manifest.chunkSize);
    writer.u32(manifest.chunkCount);
    writer.variable32(manifest.metadata);
}

function readManifest(reader: Reader): EncodedManifest {
    const manifest: EncodedManifest = {
        fileId: reader.bytes(FILE_ID_BYTES),
        fileKey: reader.bytes(KEY_BYTES),
        commitment: reader.bytes(HASH_BYTES),
        blobId: reader.bytes(HASH_BYTES),
        plaintextLength: reader.u32(),
        chunkSize: reader.u32(),
        chunkCount: reader.u32(),
        metadata: reader.variable32(MAXIMUM_FRAME_BYTES),
    };
    const expectedCount = Math.max(1, Math.ceil(manifest.plaintextLength / ATTACHMENT_CHUNK_BYTES));
    if (
        manifest.plaintextLength > MAXIMUM_ATTACHMENT_BYTES ||
        manifest.chunkSize !== ATTACHMENT_CHUNK_BYTES ||
        manifest.chunkCount !== expectedCount
    ) {
        throw new ChatCodecError("Inconsistent attachment manifest");
    }
    return manifest;
}

export function encodeFrame(frame: DecodedFrame): Uint8Array {
    if (frame.attachments.length > MAXIMUM_ATTACHMENTS) {
        throw new ChatCodecError("Too many attachments");
    }
    const writer = new Writer();
    writer.bytes(FRAME_MAGIC);
    writer.bytes(frame.messageId, MESSAGE_ID_BYTES);
    writer.u64(frame.claimedAt);
    writer.variable32(frame.body);
    writer.u8(frame.attachments.length);
    for (const manifest of frame.attachments) writeManifest(writer, manifest);
    return writer.finish(MAXIMUM_FRAME_BYTES);
}

export function decodeFrame(bytes: Uint8Array): DecodedFrame {
    const reader = new Reader(bytes, MAXIMUM_FRAME_BYTES);
    reader.expect(FRAME_MAGIC);
    const messageId = reader.bytes(MESSAGE_ID_BYTES);
    const claimedAt = reader.u64Number();
    const body = reader.variable32(MAXIMUM_FRAME_BYTES);
    const count = reader.u8();
    if (count > MAXIMUM_ATTACHMENTS) throw new ChatCodecError("Too many attachments");
    const attachments: EncodedManifest[] = [];
    for (let index = 0; index < count; index += 1) attachments.push(readManifest(reader));
    reader.end();
    return { messageId, claimedAt, body, attachments };
}

export function encodeOutbox(record: OutboxRecord): Uint8Array {
    if (record.attachments.length > MAXIMUM_ATTACHMENTS) {
        throw new ChatCodecError("Too many attachment intents");
    }
    const writer = new Writer();
    writer.bytes(OUTBOX_MAGIC);
    writer.u8(
        record.status === "preparing"
            ? 0
            : record.status === "ready"
              ? 1
              : record.status === "handed-off"
                ? 2
                : 3,
    );
    writer.u64(record.enqueueSequence);
    writer.bytes(record.conversationId, GROUP_ID_BYTES);
    writer.bytes(record.messageId, MESSAGE_ID_BYTES);
    writer.u64(record.claimedAt);
    writer.variable32(record.body);
    writer.u8(record.attachments.length);
    for (const attachment of record.attachments) {
        writer.u8(
            attachment.stageState === "new"
                ? 0
                : attachment.stageState === "staging"
                  ? 1
                  : attachment.stageState === "staged"
                    ? 2
                    : 3,
        );
        writer.variable16(encoder.encode(attachment.sourceId));
        writer.variable32(attachment.metadata);
        writer.bytes(attachment.fileId, FILE_ID_BYTES);
        writer.bytes(attachment.fileKey, KEY_BYTES);
        writer.bytes(attachment.sourceHash, HASH_BYTES);
        writer.u32(attachment.plaintextLength);
        writer.u8(attachment.manifest === undefined ? 0 : 1);
        if (attachment.manifest !== undefined) writeManifest(writer, attachment.manifest);
    }
    writer.u8(record.frameDigest === undefined ? 0 : 1);
    if (record.frameDigest !== undefined) writer.bytes(record.frameDigest, HASH_BYTES);
    writer.variable16(encoder.encode(record.lastError?.code ?? ""));
    writer.variable16(encoder.encode(record.lastError?.message ?? ""));
    return writer.finish(3 * 1024 * 1024);
}

export function decodeOutbox(bytes: Uint8Array): OutboxRecord {
    try {
        const reader = new Reader(bytes, 3 * 1024 * 1024);
        reader.expect(OUTBOX_MAGIC);
        const state = reader.u8();
        if (state > 3) throw new ChatCodecError("Unknown outbox state");
        const record: OutboxRecord = {
            status:
                state === 0
                    ? "preparing"
                    : state === 1
                      ? "ready"
                      : state === 2
                        ? "handed-off"
                        : "failed",
            enqueueSequence: reader.u64Bigint(),
            conversationId: reader.bytes(GROUP_ID_BYTES),
            messageId: reader.bytes(MESSAGE_ID_BYTES),
            claimedAt: reader.u64Number(),
            body: reader.variable32(MAXIMUM_FRAME_BYTES),
            attachments: [],
        };
        const count = reader.u8();
        if (count > MAXIMUM_ATTACHMENTS) throw new ChatCodecError("Too many attachment intents");
        for (let index = 0; index < count; index += 1) {
            const stage = reader.u8();
            if (stage > 3) throw new ChatCodecError("Unknown attachment stage");
            let sourceId: string;
            try {
                sourceId = decoder.decode(reader.variable16(4096));
            } catch {
                throw new ChatCodecError("Invalid attachment source identifier");
            }
            const attachment: EncodedAttachmentIntent = {
                stageState:
                    stage === 0
                        ? "new"
                        : stage === 1
                          ? "staging"
                          : stage === 2
                            ? "staged"
                            : "uploaded",
                sourceId,
                metadata: reader.variable32(MAXIMUM_FRAME_BYTES),
                fileId: reader.bytes(FILE_ID_BYTES),
                fileKey: reader.bytes(KEY_BYTES),
                sourceHash: reader.bytes(HASH_BYTES),
                plaintextLength: reader.u32(),
            };
            if (attachment.plaintextLength > MAXIMUM_ATTACHMENT_BYTES) {
                throw new ChatCodecError("Attachment exceeds maximum");
            }
            const hasManifest = reader.u8();
            if (hasManifest > 1) throw new ChatCodecError("Invalid manifest flag");
            if (hasManifest === 1) {
                attachment.manifest = readManifest(reader);
                if (
                    !equalFixed(attachment.fileId, attachment.manifest.fileId) ||
                    !equalFixed(attachment.fileKey, attachment.manifest.fileKey) ||
                    !equalFixed(attachment.metadata, attachment.manifest.metadata) ||
                    attachment.plaintextLength !== attachment.manifest.plaintextLength
                ) {
                    throw new ChatCodecError("Attachment intent and manifest are inconsistent");
                }
            }
            record.attachments.push(attachment);
        }
        const hasFrameDigest = reader.u8();
        if (hasFrameDigest > 1) throw new ChatCodecError("Invalid frame digest flag");
        if (hasFrameDigest === 1) record.frameDigest = reader.bytes(HASH_BYTES);
        let errorCode: string;
        let errorMessage: string;
        try {
            errorCode = decoder.decode(reader.variable16(MAXIMUM_ERROR_BYTES));
            errorMessage = decoder.decode(reader.variable16(MAXIMUM_ERROR_BYTES));
        } catch {
            throw new ChatCodecError("Invalid outbox error");
        }
        if ((errorCode.length === 0) !== (errorMessage.length === 0)) {
            throw new ChatCodecError("Incomplete outbox error");
        }
        if (errorCode.length > 0) record.lastError = { code: errorCode, message: errorMessage };
        reader.end();
        if (
            (record.status === "ready" || record.status === "handed-off") &&
            record.attachments.some((attachment) => attachment.manifest === undefined)
        ) {
            throw new ChatCodecError("Ready outbox lacks manifest");
        }
        if (
            (record.status === "ready" || record.status === "handed-off") &&
            record.frameDigest === undefined
        ) {
            throw new ChatCodecError("Ready outbox lacks frame digest");
        }
        if (record.status === "failed" && record.lastError === undefined) {
            throw new ChatCodecError("Failed outbox lacks durable error");
        }
        validateOutboxFrameBounds(record);
        return record;
    } catch (error: unknown) {
        throw new ChatStoreCorruptionError(
            error instanceof Error
                ? `Corrupt chat outbox: ${error.message}`
                : "Corrupt chat outbox",
        );
    }
}

function validateOutboxFrameBounds(record: OutboxRecord): void {
    const manifests: EncodedManifest[] = record.attachments.map((attachment) => {
        if (attachment.manifest !== undefined) return attachment.manifest;
        const chunkCount = Math.max(
            1,
            Math.ceil(attachment.plaintextLength / ATTACHMENT_CHUNK_BYTES),
        );
        return {
            metadata: attachment.metadata,
            fileId: attachment.fileId,
            fileKey: attachment.fileKey,
            commitment: new Uint8Array(HASH_BYTES),
            blobId: new Uint8Array(HASH_BYTES),
            plaintextLength: attachment.plaintextLength,
            chunkSize: ATTACHMENT_CHUNK_BYTES,
            chunkCount,
        };
    });
    encodeFrame({
        messageId: record.messageId,
        claimedAt: record.claimedAt,
        body: record.body,
        attachments: manifests,
    });
}

function equalFixed(left: Uint8Array, right: Uint8Array): boolean {
    let difference = left.length ^ right.length;
    const length = Math.max(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}

export function encodeProjection(sender: Uint8Array, frame: Uint8Array): Uint8Array {
    const writer = new Writer();
    writer.bytes(PROJECTION_MAGIC);
    writer.bytes(sender, IDENTITY_BYTES);
    writer.variable32(frame);
    return writer.finish(MAXIMUM_FRAME_BYTES + 64);
}

export function decodeProjection(bytes: Uint8Array): {
    sender: Uint8Array;
    frame: Uint8Array;
} {
    try {
        const reader = new Reader(bytes, MAXIMUM_FRAME_BYTES + 64);
        reader.expect(PROJECTION_MAGIC);
        const sender = reader.bytes(IDENTITY_BYTES);
        const frame = reader.variable32(MAXIMUM_FRAME_BYTES);
        reader.end();
        decodeFrame(frame);
        return { sender, frame };
    } catch (error: unknown) {
        throw new ChatStoreCorruptionError(
            error instanceof Error
                ? `Corrupt chat projection: ${error.message}`
                : "Corrupt chat projection",
        );
    }
}

export function encodeCursor(sequence: bigint): Uint8Array {
    const writer = new Writer();
    writer.u64(sequence);
    return writer.finish(8);
}

export function decodeCursor(bytes: Uint8Array): bigint {
    try {
        const reader = new Reader(bytes, 8);
        const value = reader.u64Bigint();
        reader.end();
        return value;
    } catch (error: unknown) {
        throw new ChatStoreCorruptionError(
            error instanceof Error
                ? `Corrupt chat cursor: ${error.message}`
                : "Corrupt chat cursor",
        );
    }
}
