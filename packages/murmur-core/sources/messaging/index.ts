import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "../crypto/index.js";
import { createRelayBlob, verifyRelayBlob, type RelayBlob } from "../transport/index.js";
import { canonicalJsonBytes, decodeBase64Url, encodeBase64Url } from "../utils/index.js";
import {
    encodePrivateMessage,
    MAX_FILE_BYTES,
    validateFileDescriptor,
} from "./impl/messageCodec.js";
import type { EncryptedFile, EncryptedFileDescriptor, PrivateMessage } from "./types.js";

export {
    decodePrivateMessage,
    encodePrivateMessage,
    MAX_FILE_BYTES,
    MAX_MESSAGE_ATTACHMENTS,
    MAX_MESSAGE_BYTES,
} from "./impl/messageCodec.js";
export type { EncryptedFile, EncryptedFileDescriptor, PrivateMessage } from "./types.js";

function fileAssociatedData(
    descriptor: Pick<EncryptedFileDescriptor, "mediaType" | "name" | "plaintextBytes" | "version">,
): Uint8Array {
    return canonicalJsonBytes({
        mediaType: descriptor.mediaType,
        name: descriptor.name,
        plaintextBytes: descriptor.plaintextBytes,
        version: descriptor.version,
    });
}

/** Encrypt a file before any relay upload. */
export function encryptFile(
    plaintext: Uint8Array,
    options: { readonly name: string; readonly mediaType?: string },
): EncryptedFile {
    if (plaintext.length > MAX_FILE_BYTES) {
        throw new Error(`File exceeds ${MAX_FILE_BYTES} bytes`);
    }
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const metadata = {
        version: 1 as const,
        name: options.name,
        mediaType: options.mediaType ?? "application/octet-stream",
        plaintextBytes: plaintext.length,
    };
    const ciphertext = gcm(key, nonce, fileAssociatedData(metadata)).encrypt(plaintext);
    const blob = createRelayBlob(ciphertext);
    const descriptor: EncryptedFileDescriptor = {
        ...metadata,
        blobId: blob.id,
        key,
        nonce,
    };
    validateFileDescriptor(descriptor);
    return { descriptor, blob };
}

/** Authenticate and decrypt a downloaded relay blob. */
export function decryptFile(descriptor: EncryptedFileDescriptor, blob: RelayBlob): Uint8Array {
    validateFileDescriptor(descriptor);
    if (
        blob.bytes.length > MAX_FILE_BYTES + 16 ||
        blob.id !== descriptor.blobId ||
        !verifyRelayBlob(blob) ||
        decodeBase64Url(blob.id).length !== 32
    ) {
        throw new Error("Encrypted file blob failed integrity validation");
    }
    const plaintext = gcm(descriptor.key, descriptor.nonce, fileAssociatedData(descriptor)).decrypt(
        blob.bytes,
    );
    if (plaintext.length !== descriptor.plaintextBytes) {
        throw new Error("Encrypted file plaintext size does not match its descriptor");
    }
    return plaintext;
}

/** Create validated application data for a private message. */
export function createPrivateMessage(
    text: string,
    attachments: readonly EncryptedFileDescriptor[] = [],
    now: number = Date.now(),
): PrivateMessage {
    const message: PrivateMessage = {
        version: 1,
        id: encodeBase64Url(randomBytes(24)),
        sentAt: now,
        text,
        attachments: [...attachments],
    };
    encodePrivateMessage(message);
    return message;
}
