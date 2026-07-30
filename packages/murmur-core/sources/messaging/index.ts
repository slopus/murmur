import { gcm } from "@noble/ciphers/aes";
import {
    openBox,
    hashBytes,
    randomBytes,
    sealBox,
    signBytes,
    verifyBytes,
    type IdentityKeyPair,
    type IdentityPublicKeys,
} from "../crypto/index.js";
import {
    deserializePublicIdentity,
    identityId,
    serializePublicIdentity,
} from "../identity/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
    createRelayBlob,
    verifyRelayBlob,
    type RelayBlob,
} from "../transport/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import {
    decodePrivateMessage,
    encodePrivateMessage,
    MAX_FILE_BYTES,
    MAX_MESSAGE_BYTES,
    validateFileDescriptor,
} from "./impl/messageCodec.js";
import type {
    AcceptedPrivateMessage,
    EncryptedFile,
    EncryptedFileDescriptor,
    EncryptedPrivateMessage,
    OpenedPrivateMessage,
    PrivateMessage,
} from "./types.js";

export {
    decodePrivateMessage,
    encodePrivateMessage,
    MAX_FILE_BYTES,
    MAX_MESSAGE_ATTACHMENTS,
    MAX_MESSAGE_BYTES,
} from "./impl/messageCodec.js";
export type {
    AcceptedPrivateMessage,
    EncryptedFile,
    EncryptedFileDescriptor,
    EncryptedPrivateMessage,
    OpenedPrivateMessage,
    PrivateMessage,
} from "./types.js";

const MAX_DIRECT_PLAINTEXT_BYTES = Math.ceil((MAX_MESSAGE_BYTES * 4) / 3) + 512;
const MAX_DIRECT_CIPHERTEXT_BYTES = MAX_DIRECT_PLAINTEXT_BYTES + 16;
const MAX_DIRECT_CIPHERTEXT_CHARACTERS = Math.min(
    Math.ceil((MAX_DIRECT_CIPHERTEXT_BYTES * 4) / 3),
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
);
const MAX_DIRECT_WIRE_BYTES = MAX_RELAY_EVENT_PAYLOAD_BYTES;
const MAX_MESSAGE_BASE64URL_CHARACTERS = Math.ceil((MAX_MESSAGE_BYTES * 4) / 3);
const DIRECT_MESSAGE_REPLAY_PREFIX = "private-message-replay/v1";

function directSignaturePayload(messageBytes: Uint8Array, recipient: string): Uint8Array {
    return canonicalJsonBytes({
        message: encodeBase64Url(messageBytes),
        recipient,
        version: 1,
    });
}

function directAssociatedData(
    sender: EncryptedPrivateMessage["sender"],
    recipient: string,
): Uint8Array {
    return canonicalJsonBytes({
        recipient,
        sender: {
            encryptionKey: sender.encryptionKey,
            signingKey: sender.signingKey,
        },
        version: 1,
    });
}

function validateCanonicalBase64Url(value: string, bytes?: number): Uint8Array {
    if (bytes !== undefined && value.length > Math.ceil((bytes * 4) / 3)) {
        throw new Error("Invalid encrypted private message");
    }
    const decoded = decodeBase64Url(value);
    if ((bytes !== undefined && decoded.length !== bytes) || encodeBase64Url(decoded) !== value) {
        throw new Error("Invalid encrypted private message");
    }
    return decoded;
}

function exactOwnData(value: unknown, fields: readonly string[]): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("Invalid encrypted private message");
    }
    const keys = Reflect.ownKeys(value);
    if (
        keys.length !== fields.length ||
        keys.some((key) => typeof key !== "string" || !fields.includes(key))
    ) {
        throw new Error("Invalid encrypted private message");
    }
    const result: Record<string, unknown> = {};
    for (const field of fields) {
        const descriptor = Object.getOwnPropertyDescriptor(value, field);
        if (descriptor === undefined || !("value" in descriptor)) {
            throw new Error("Invalid encrypted private message");
        }
        result[field] = descriptor.value;
    }
    return result;
}

function normalizeEncryptedPrivateMessage(value: unknown): EncryptedPrivateMessage {
    const envelope = exactOwnData(value, [
        "version",
        "sender",
        "recipient",
        "ephemeralPublicKey",
        "nonce",
        "ciphertext",
    ]);
    const sender = exactOwnData(envelope.sender, ["signingKey", "encryptionKey"]);
    if (
        envelope.version !== 1 ||
        typeof sender.signingKey !== "string" ||
        typeof sender.encryptionKey !== "string" ||
        typeof envelope.recipient !== "string" ||
        typeof envelope.ephemeralPublicKey !== "string" ||
        typeof envelope.nonce !== "string" ||
        typeof envelope.ciphertext !== "string"
    ) {
        throw new Error("Invalid encrypted private message");
    }
    const encrypted: EncryptedPrivateMessage = {
        version: 1,
        sender: {
            signingKey: sender.signingKey,
            encryptionKey: sender.encryptionKey,
        },
        recipient: envelope.recipient,
        ephemeralPublicKey: envelope.ephemeralPublicKey,
        nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
    };
    if (encrypted.sender.signingKey.length > 43 || encrypted.sender.encryptionKey.length > 43) {
        throw new Error("Invalid encrypted private message");
    }
    deserializePublicIdentity(encrypted.sender);
    validateCanonicalBase64Url(encrypted.recipient, 32);
    validateCanonicalBase64Url(encrypted.ephemeralPublicKey, 32);
    validateCanonicalBase64Url(encrypted.nonce, 12);
    if (encrypted.ciphertext.length > MAX_DIRECT_CIPHERTEXT_CHARACTERS) {
        throw new Error("Encrypted private message is too large");
    }
    const ciphertext = validateCanonicalBase64Url(encrypted.ciphertext);
    if (ciphertext.length > MAX_DIRECT_CIPHERTEXT_BYTES) {
        throw new Error("Encrypted private message is too large");
    }
    return encrypted;
}

/** Encode a bounded direct-message ciphertext for a relay event payload. */
export function encodeEncryptedPrivateMessage(encrypted: EncryptedPrivateMessage): Uint8Array {
    const normalized = normalizeEncryptedPrivateMessage(encrypted);
    const bytes = utf8Encode(JSON.stringify(normalized));
    if (bytes.length > MAX_DIRECT_WIRE_BYTES) {
        throw new Error("Encrypted private message wire payload is too large");
    }
    return bytes;
}

/** Decode and strictly validate a direct-message ciphertext from a relay event. */
export function decodeEncryptedPrivateMessage(bytes: Uint8Array): EncryptedPrivateMessage {
    if (bytes.length > MAX_DIRECT_WIRE_BYTES) {
        throw new Error("Encrypted private message wire payload is too large");
    }
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    return normalizeEncryptedPrivateMessage(decoded);
}

/** Sign and encrypt one private message directly to a contact identity. */
export function encryptPrivateMessageForContact(
    sender: IdentityKeyPair,
    recipient: IdentityPublicKeys,
    message: PrivateMessage,
): EncryptedPrivateMessage {
    const messageBytes = encodePrivateMessage(message);
    let plaintext: Uint8Array | undefined;
    let signaturePayload: Uint8Array | undefined;
    let wire: Uint8Array | undefined;
    try {
        const recipientId = identityId(recipient);
        signaturePayload = directSignaturePayload(messageBytes, recipientId);
        const signature = signBytes(sender, signaturePayload);
        plaintext = utf8Encode(
            JSON.stringify({
                message: encodeBase64Url(messageBytes),
                signature: encodeBase64Url(signature),
            }),
        );
        const serializedSender = serializePublicIdentity(sender);
        if (plaintext.length > MAX_DIRECT_PLAINTEXT_BYTES) {
            throw new Error("Encrypted private message plaintext is too large");
        }
        const box = sealBox(
            recipient,
            plaintext,
            directAssociatedData(serializedSender, recipientId),
        );
        const encrypted: EncryptedPrivateMessage = {
            version: 1,
            sender: serializedSender,
            recipient: recipientId,
            ephemeralPublicKey: encodeBase64Url(box.ephemeralPublicKey),
            nonce: encodeBase64Url(box.nonce),
            ciphertext: encodeBase64Url(box.ciphertext),
        };
        wire = encodeEncryptedPrivateMessage(encrypted);
        return encrypted;
    } finally {
        zeroBytes(messageBytes);
        if (signaturePayload !== undefined) {
            zeroBytes(signaturePayload);
        }
        if (plaintext !== undefined) {
            zeroBytes(plaintext);
        }
        if (wire !== undefined) {
            zeroBytes(wire);
        }
    }
}

/** Decrypt a direct message and authenticate its claimed sender identity. */
export function decryptPrivateMessageFromContact(
    recipient: IdentityKeyPair,
    encryptedValue: EncryptedPrivateMessage,
): OpenedPrivateMessage {
    const encrypted = normalizeEncryptedPrivateMessage(encryptedValue);
    if (encrypted.recipient !== identityId(recipient)) {
        throw new Error("Encrypted private message is not addressed to this identity");
    }
    const sender = deserializePublicIdentity(encrypted.sender);
    const plaintext = openBox(
        recipient,
        {
            ephemeralPublicKey: decodeBase64Url(encrypted.ephemeralPublicKey),
            nonce: decodeBase64Url(encrypted.nonce),
            ciphertext: decodeBase64Url(encrypted.ciphertext),
        },
        directAssociatedData(encrypted.sender, encrypted.recipient),
    );
    let messageBytes: Uint8Array | undefined;
    let signaturePayload: Uint8Array | undefined;
    try {
        if (plaintext.length > MAX_DIRECT_PLAINTEXT_BYTES) {
            throw new Error("Encrypted private message plaintext is too large");
        }
        const decoded: unknown = JSON.parse(utf8Decode(plaintext));
        if (
            typeof decoded !== "object" ||
            decoded === null ||
            Array.isArray(decoded) ||
            !("message" in decoded) ||
            typeof decoded.message !== "string" ||
            decoded.message.length > MAX_MESSAGE_BASE64URL_CHARACTERS ||
            !("signature" in decoded) ||
            typeof decoded.signature !== "string" ||
            Object.keys(decoded).some((key) => !["message", "signature"].includes(key))
        ) {
            throw new Error("Invalid encrypted private message plaintext");
        }
        messageBytes = validateCanonicalBase64Url(decoded.message);
        if (messageBytes.length > MAX_MESSAGE_BYTES) {
            throw new Error("Encrypted private message content is too large");
        }
        const signature = validateCanonicalBase64Url(decoded.signature, 64);
        signaturePayload = directSignaturePayload(messageBytes, encrypted.recipient);
        if (!verifyBytes(sender, signaturePayload, signature)) {
            throw new Error("Invalid encrypted private message signature");
        }
        return {
            identity: sender,
            message: decodePrivateMessage(messageBytes),
        };
    } finally {
        if (messageBytes !== undefined) {
            zeroBytes(messageBytes);
        }
        if (signaturePayload !== undefined) {
            zeroBytes(signaturePayload);
        }
        zeroBytes(plaintext);
    }
}

/**
 * Authenticate a direct message and atomically record its sender/message ID.
 *
 * The persistence callback runs inside the same store transaction as the replay
 * marker and is invoked only for a first-seen authenticated message.
 * Callers may acknowledge the relay delivery only after this function resolves.
 * A duplicate is safe to acknowledge; an ID collision throws and remains
 * unacknowledged for explicit quarantine or operator handling.
 */
export async function acceptPrivateMessageFromContact(
    store: MurmurStore,
    recipient: IdentityKeyPair,
    encrypted: EncryptedPrivateMessage,
    persist: (transaction: StoreTransaction, opened: OpenedPrivateMessage) => Promise<void>,
): Promise<AcceptedPrivateMessage> {
    const opened = decryptPrivateMessageFromContact(recipient, encrypted);
    let messageBytes: Uint8Array | undefined;
    let messageIdBytes: Uint8Array | undefined;
    let messageIdDigest: Uint8Array | undefined;
    let messageDigest: Uint8Array | undefined;
    let replayRecord: Uint8Array | undefined;
    let completed = false;

    try {
        messageBytes = encodePrivateMessage(opened.message);
        messageIdBytes = utf8Encode(opened.message.id);
        messageIdDigest = hashBytes(messageIdBytes);
        messageDigest = hashBytes(messageBytes);
        const replayKey = `${DIRECT_MESSAGE_REPLAY_PREFIX}/${identityId(recipient)}/${identityId(
            opened.identity,
        )}/${encodeBase64Url(messageIdDigest)}`;
        const record = canonicalJsonBytes({
            fingerprint: encodeBase64Url(messageDigest),
            id: opened.message.id,
            version: 1,
        });
        replayRecord = record;
        const status = await store.transaction(async (transaction) => {
            const existing = await transaction.get(replayKey);
            if (existing === undefined) {
                await persist(transaction, opened);
                await transaction.set(replayKey, record.slice());
                return "opened" as const;
            }
            if (equalBytes(existing, record)) {
                return "duplicate" as const;
            }
            throw new Error("Authenticated direct private message ID collision");
        });
        const accepted: AcceptedPrivateMessage = {
            ...opened,
            status,
        };
        completed = true;
        return accepted;
    } finally {
        if (messageBytes !== undefined) {
            zeroBytes(messageBytes);
        }
        if (messageIdBytes !== undefined) {
            zeroBytes(messageIdBytes);
        }
        if (messageIdDigest !== undefined) {
            zeroBytes(messageIdDigest);
        }
        if (messageDigest !== undefined) {
            zeroBytes(messageDigest);
        }
        if (replayRecord !== undefined) {
            zeroBytes(replayRecord);
        }
        if (!completed) {
            for (const attachment of opened.message.attachments) {
                zeroBytes(attachment.key);
                zeroBytes(attachment.nonce);
            }
        }
    }
}

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
