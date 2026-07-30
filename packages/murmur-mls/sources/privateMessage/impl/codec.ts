import { concatBytes } from "@murmur/core";
import { MLS_PROTOCOL_VERSION } from "../../cipherSuite/index.js";
import { decodeVarint, encodeOpaqueV, encodeUint16, encodeUint64 } from "../../encoding/index.js";
import type { MlsPrivateMessage } from "../types.js";

export const MLS_WIRE_FORMAT_PRIVATE_MESSAGE = 2;
export const MLS_CONTENT_TYPE_APPLICATION = 1;
export const MAXIMUM_MLS_APPLICATION_BYTES = 1024 * 1024;
export const MAXIMUM_MLS_AUTHENTICATED_DATA_BYTES = 1024 * 1024;
export const MAXIMUM_MLS_PADDING_BYTES = 1024 * 1024;
const MAXIMUM_ENCRYPTED_SENDER_DATA_BYTES = 256;
const MAXIMUM_PRIVATE_CIPHERTEXT_BYTES =
    MAXIMUM_MLS_APPLICATION_BYTES + MAXIMUM_MLS_PADDING_BYTES + 4 * 1024;
const MAXIMUM_GROUP_ID_BYTES = 255;
const MAXIMUM_PRIVATE_MESSAGE_BYTES = 4 * 1024 * 1024;

export class PrivateMessageReader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS PrivateMessage");
        }
        return this.bytes[this.#offset++] ?? 0;
    }

    readUint16(): number {
        return (this.readUint8() << 8) | this.readUint8();
    }

    readUint32(): number {
        return (
            this.readUint8() * 0x1_00_00_00 +
            (this.readUint8() << 16) +
            (this.readUint8() << 8) +
            this.readUint8()
        );
    }

    readUint64(): bigint {
        let value = 0n;
        for (let index = 0; index < 8; index += 1) {
            value = (value << 8n) | BigInt(this.readUint8());
        }
        return value;
    }

    readBytes(length: number): Uint8Array {
        if (
            !Number.isSafeInteger(length) ||
            length < 0 ||
            this.#offset + length > this.bytes.length
        ) {
            throw new Error("Truncated MLS PrivateMessage bytes");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    readOpaqueV(maximumBytes: number): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS PrivateMessage vector is too large");
        }
        return this.readBytes(Number(decoded.value));
    }

    readRemaining(maximumBytes: number): Uint8Array {
        const remaining = this.bytes.length - this.#offset;
        if (remaining > maximumBytes) {
            throw new Error("MLS PrivateMessage remainder is too large");
        }
        return this.readBytes(remaining);
    }

    ensureEnd(): void {
        if (this.#offset !== this.bytes.length) {
            throw new Error("Trailing bytes in MLS PrivateMessage");
        }
    }
}

/** Encode a full RFC 9420 MLSMessage containing a PrivateMessage. */
export function encodeMlsPrivateMessage(message: MlsPrivateMessage): Uint8Array {
    if (
        message.groupId.length === 0 ||
        message.groupId.length > MAXIMUM_GROUP_ID_BYTES ||
        message.epoch < 0n ||
        message.epoch > 0xffff_ffff_ffff_ffffn ||
        message.authenticatedData.length > MAXIMUM_MLS_AUTHENTICATED_DATA_BYTES ||
        message.encryptedSenderData.length > MAXIMUM_ENCRYPTED_SENDER_DATA_BYTES ||
        message.ciphertext.length > MAXIMUM_PRIVATE_CIPHERTEXT_BYTES
    ) {
        throw new Error("Invalid MLS PrivateMessage");
    }
    const encoded = concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_PRIVATE_MESSAGE),
        encodeOpaqueV(message.groupId),
        encodeUint64(message.epoch),
        new Uint8Array([MLS_CONTENT_TYPE_APPLICATION]),
        encodeOpaqueV(message.authenticatedData),
        encodeOpaqueV(message.encryptedSenderData),
        encodeOpaqueV(message.ciphertext),
    );
    if (encoded.length > MAXIMUM_PRIVATE_MESSAGE_BYTES) {
        throw new Error("MLS PrivateMessage is too large");
    }
    return encoded;
}

/** Decode the supported application-only RFC 9420 PrivateMessage profile. */
export function decodeMlsPrivateMessage(bytes: Uint8Array): MlsPrivateMessage {
    if (bytes.length > MAXIMUM_PRIVATE_MESSAGE_BYTES) {
        throw new Error("MLS PrivateMessage is too large");
    }
    const reader = new PrivateMessageReader(bytes);
    if (
        reader.readUint16() !== MLS_PROTOCOL_VERSION ||
        reader.readUint16() !== MLS_WIRE_FORMAT_PRIVATE_MESSAGE
    ) {
        throw new Error("Unsupported MLS message version or wire format");
    }
    const message: MlsPrivateMessage = {
        groupId: reader.readOpaqueV(MAXIMUM_GROUP_ID_BYTES),
        epoch: reader.readUint64(),
        authenticatedData: new Uint8Array(),
        encryptedSenderData: new Uint8Array(),
        ciphertext: new Uint8Array(),
    };
    if (reader.readUint8() !== MLS_CONTENT_TYPE_APPLICATION) {
        throw new Error("Expected MLS application content");
    }
    const decoded: MlsPrivateMessage = {
        ...message,
        authenticatedData: reader.readOpaqueV(MAXIMUM_MLS_AUTHENTICATED_DATA_BYTES),
        encryptedSenderData: reader.readOpaqueV(MAXIMUM_ENCRYPTED_SENDER_DATA_BYTES),
        ciphertext: reader.readOpaqueV(MAXIMUM_PRIVATE_CIPHERTEXT_BYTES),
    };
    reader.ensureEnd();
    // Apply encoder-side lower bounds as well.
    encodeMlsPrivateMessage(decoded);
    return decoded;
}
