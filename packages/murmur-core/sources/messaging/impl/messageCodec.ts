import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type { EncryptedFileDescriptor, PrivateMessage } from "../types.js";

interface SerializedFileDescriptor {
    readonly version: 1;
    readonly blobId: string;
    readonly key: string;
    readonly nonce: string;
    readonly name: string;
    readonly mediaType: string;
    readonly plaintextBytes: number;
}

interface SerializedPrivateMessage {
    readonly version: 1;
    readonly id: string;
    readonly sentAt: number;
    readonly text: string;
    readonly attachments: readonly SerializedFileDescriptor[];
}

export const MAX_MESSAGE_BYTES = 1024 * 1024;
export const MAX_MESSAGE_ATTACHMENTS = 64;
export const MAX_FILE_BYTES = 64 * 1024 * 1024 - 16;

/** Validate a canonical base64url identifier encoding exactly 24 bytes. */
export function validatePrivateMessageId(id: string): void {
    if (!/^[A-Za-z0-9_-]{32}$/.test(id)) {
        throw new Error("Invalid private message ID");
    }
    const decoded = decodeBase64Url(id);
    if (decoded.length !== 24 || encodeBase64Url(decoded) !== id) {
        throw new Error("Invalid private message ID");
    }
}

function unsafeFileName(name: string): boolean {
    const windowsBaseName = name.split(".")[0]?.toUpperCase() ?? "";
    return (
        name.length === 0 ||
        utf8Encode(name).length > 255 ||
        name === "." ||
        name === ".." ||
        /[/\\:]/.test(name) ||
        [...name].some((character) => character.charCodeAt(0) < 32) ||
        /[ .]$/.test(name) ||
        /^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$/.test(windowsBaseName)
    );
}

export function validateFileDescriptor(descriptor: EncryptedFileDescriptor): void {
    if (
        descriptor.version !== 1 ||
        descriptor.key.length !== 32 ||
        descriptor.nonce.length !== 12 ||
        !/^[A-Za-z0-9_-]{43}$/.test(descriptor.blobId) ||
        decodeBase64Url(descriptor.blobId).length !== 32 ||
        !Number.isSafeInteger(descriptor.plaintextBytes) ||
        descriptor.plaintextBytes < 0 ||
        descriptor.plaintextBytes > MAX_FILE_BYTES ||
        unsafeFileName(descriptor.name) ||
        descriptor.mediaType.length === 0 ||
        descriptor.mediaType.length > 255
    ) {
        throw new Error("Invalid encrypted file descriptor");
    }
}

function serializeFileDescriptor(descriptor: EncryptedFileDescriptor): SerializedFileDescriptor {
    validateFileDescriptor(descriptor);
    return {
        version: 1,
        blobId: descriptor.blobId,
        key: encodeBase64Url(descriptor.key),
        nonce: encodeBase64Url(descriptor.nonce),
        name: descriptor.name,
        mediaType: descriptor.mediaType,
        plaintextBytes: descriptor.plaintextBytes,
    };
}

function deserializeFileDescriptor(descriptor: unknown): EncryptedFileDescriptor {
    if (typeof descriptor !== "object" || descriptor === null || Array.isArray(descriptor)) {
        throw new Error("Invalid encrypted file descriptor");
    }
    const value = descriptor as Record<string, unknown>;
    if (
        value.version !== 1 ||
        typeof value.blobId !== "string" ||
        typeof value.key !== "string" ||
        typeof value.nonce !== "string" ||
        typeof value.name !== "string" ||
        typeof value.mediaType !== "string" ||
        typeof value.plaintextBytes !== "number" ||
        Object.keys(value).some(
            (key) =>
                ![
                    "version",
                    "blobId",
                    "key",
                    "nonce",
                    "name",
                    "mediaType",
                    "plaintextBytes",
                ].includes(key),
        )
    ) {
        throw new Error("Invalid encrypted file descriptor");
    }
    const serialized = value as unknown as SerializedFileDescriptor;
    const result: EncryptedFileDescriptor = {
        version: serialized.version,
        blobId: serialized.blobId,
        key: decodeBase64Url(serialized.key),
        nonce: decodeBase64Url(serialized.nonce),
        name: serialized.name,
        mediaType: serialized.mediaType,
        plaintextBytes: serialized.plaintextBytes,
    };
    validateFileDescriptor(result);
    return result;
}

/** Encode private-message application data for group encryption. */
export function encodePrivateMessage(message: PrivateMessage): Uint8Array {
    if (
        message.version !== 1 ||
        (() => {
            try {
                validatePrivateMessageId(message.id);
                return false;
            } catch {
                return true;
            }
        })() ||
        !Number.isSafeInteger(message.sentAt) ||
        message.sentAt < 0 ||
        message.text.length > MAX_MESSAGE_BYTES ||
        message.attachments.length > MAX_MESSAGE_ATTACHMENTS
    ) {
        throw new Error("Invalid private message");
    }
    const serialized: SerializedPrivateMessage = {
        version: 1,
        id: message.id,
        sentAt: message.sentAt,
        text: message.text,
        attachments: message.attachments.map(serializeFileDescriptor),
    };
    const bytes = utf8Encode(JSON.stringify(serialized));
    if (bytes.length > MAX_MESSAGE_BYTES) {
        throw new Error(`Private message exceeds ${MAX_MESSAGE_BYTES} bytes`);
    }
    return bytes;
}

/** Decode and validate private-message application data after group decryption. */
export function decodePrivateMessage(bytes: Uint8Array): PrivateMessage {
    if (bytes.length > MAX_MESSAGE_BYTES) {
        throw new Error(`Private message exceeds ${MAX_MESSAGE_BYTES} bytes`);
    }
    const value: unknown = JSON.parse(utf8Decode(bytes));
    if (
        typeof value !== "object" ||
        value === null ||
        Array.isArray(value) ||
        !("version" in value) ||
        value.version !== 1 ||
        !("id" in value) ||
        typeof value.id !== "string" ||
        !("sentAt" in value) ||
        typeof value.sentAt !== "number" ||
        !("text" in value) ||
        typeof value.text !== "string" ||
        !("attachments" in value) ||
        !Array.isArray(value.attachments) ||
        value.attachments.length > MAX_MESSAGE_ATTACHMENTS ||
        Object.keys(value).some(
            (key) => !["version", "id", "sentAt", "text", "attachments"].includes(key),
        )
    ) {
        throw new Error("Invalid private message");
    }

    const serialized = value as unknown as SerializedPrivateMessage;
    const message: PrivateMessage = {
        version: 1,
        id: serialized.id,
        sentAt: serialized.sentAt,
        text: serialized.text,
        attachments: serialized.attachments.map((descriptor) =>
            deserializeFileDescriptor(descriptor),
        ),
    };
    // Apply every encoder-side invariant to decoded data.
    encodePrivateMessage(message);
    return message;
}
