import { concatBytes, equalBytes, randomBytes, zeroBytes } from "@slopus/murmur";
import {
    MLS_AEAD_KEY_LENGTH,
    MLS_AEAD_NONCE_LENGTH,
    MLS_HASH_LENGTH,
    MLS_PROTOCOL_VERSION,
    mlsAeadOpen,
    mlsAeadSeal,
    mlsExpandWithLabel,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import { encodeUint16, encodeUint32, encodeUint64, encodeOpaqueV } from "../encoding/index.js";
import { encodeMlsGroupContext } from "../groupContext/index.js";
import { destroyMlsGenerationKey, type MlsGenerationKey } from "../secretTree/index.js";
import {
    decodeMlsPrivateMessage,
    encodeMlsPrivateMessage,
    MAXIMUM_MLS_APPLICATION_BYTES,
    MAXIMUM_MLS_AUTHENTICATED_DATA_BYTES,
    MAXIMUM_MLS_PADDING_BYTES,
    MLS_CONTENT_TYPE_APPLICATION,
    MLS_WIRE_FORMAT_PRIVATE_MESSAGE,
    PrivateMessageReader,
} from "./impl/codec.js";
import type {
    MlsPrivateMessage,
    OpenedMlsApplicationMessage,
    OpenMlsApplicationMessageOptions,
    SealMlsApplicationMessageOptions,
} from "./types.js";

export type {
    MlsPrivateMessage,
    OpenedMlsApplicationMessage,
    OpenMlsApplicationMessageOptions,
    SealMlsApplicationMessageOptions,
} from "./types.js";
export { decodeMlsPrivateMessage, encodeMlsPrivateMessage } from "./impl/codec.js";

const MLS_SENDER_TYPE_MEMBER = 1;
const REUSE_GUARD_BYTES = 4;
const SIGNATURE_BYTES = 64;

interface SenderData {
    readonly sender: number;
    readonly generation: number;
    readonly reuseGuard: Uint8Array;
}

function validateUint32(value: number, name: string): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new Error(`Invalid MLS ${name}`);
    }
}

function senderDataAad(message: Pick<MlsPrivateMessage, "epoch" | "groupId">): Uint8Array {
    return concatBytes(
        encodeOpaqueV(message.groupId),
        encodeUint64(message.epoch),
        new Uint8Array([MLS_CONTENT_TYPE_APPLICATION]),
    );
}

function privateContentAad(
    message: Pick<MlsPrivateMessage, "authenticatedData" | "epoch" | "groupId">,
): Uint8Array {
    return concatBytes(senderDataAad(message), encodeOpaqueV(message.authenticatedData));
}

function encodeSenderData(senderData: SenderData): Uint8Array {
    validateUint32(senderData.sender, "sender");
    validateUint32(senderData.generation, "generation");
    if (senderData.reuseGuard.length !== REUSE_GUARD_BYTES) {
        throw new Error("Invalid MLS reuse guard");
    }
    return concatBytes(
        encodeUint32(senderData.sender),
        encodeUint32(senderData.generation),
        senderData.reuseGuard,
    );
}

function decodeSenderData(bytes: Uint8Array): SenderData {
    const reader = new PrivateMessageReader(bytes);
    const senderData: SenderData = {
        sender: reader.readUint32(),
        generation: reader.readUint32(),
        reuseGuard: reader.readBytes(REUSE_GUARD_BYTES),
    };
    reader.ensureEnd();
    return senderData;
}

function encodeFramedContentTbs(
    options: Pick<SealMlsApplicationMessageOptions, "applicationData" | "context" | "sender"> & {
        readonly authenticatedData: Uint8Array;
    },
): Uint8Array {
    validateUint32(options.sender, "sender");
    return concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_PRIVATE_MESSAGE),
        encodeOpaqueV(options.context.groupId),
        encodeUint64(options.context.epoch),
        new Uint8Array([MLS_SENDER_TYPE_MEMBER]),
        encodeUint32(options.sender),
        encodeOpaqueV(options.authenticatedData),
        new Uint8Array([MLS_CONTENT_TYPE_APPLICATION]),
        encodeOpaqueV(options.applicationData),
        encodeMlsGroupContext(options.context),
    );
}

function encodePrivateContent(
    applicationData: Uint8Array,
    signature: Uint8Array,
    paddingBytes: number,
): Uint8Array {
    if (
        applicationData.length > MAXIMUM_MLS_APPLICATION_BYTES ||
        signature.length !== SIGNATURE_BYTES ||
        !Number.isSafeInteger(paddingBytes) ||
        paddingBytes < 0 ||
        paddingBytes > MAXIMUM_MLS_PADDING_BYTES
    ) {
        throw new Error("Invalid MLS private content");
    }
    return concatBytes(
        encodeOpaqueV(applicationData),
        encodeOpaqueV(signature),
        new Uint8Array(paddingBytes),
    );
}

function decodePrivateContent(bytes: Uint8Array): {
    readonly applicationData: Uint8Array;
    readonly signature: Uint8Array;
} {
    const reader = new PrivateMessageReader(bytes);
    const applicationData = reader.readOpaqueV(MAXIMUM_MLS_APPLICATION_BYTES);
    const signature = reader.readOpaqueV(SIGNATURE_BYTES);
    const padding = reader.readRemaining(MAXIMUM_MLS_PADDING_BYTES);
    if (signature.length !== SIGNATURE_BYTES || padding.some((byte) => byte !== 0)) {
        throw new Error("Invalid MLS private content");
    }
    return { applicationData, signature };
}

function ciphertextSample(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length < MLS_HASH_LENGTH) {
        throw new Error("MLS ciphertext is too short for sender-data derivation");
    }
    return ciphertext.slice(0, MLS_HASH_LENGTH);
}

function deriveSenderDataKeyAndNonce(
    senderDataSecret: Uint8Array,
    ciphertext: Uint8Array,
): { readonly key: Uint8Array; readonly nonce: Uint8Array } {
    if (senderDataSecret.length !== MLS_HASH_LENGTH) {
        throw new Error("MLS sender-data secret must be 32 bytes");
    }
    const sample = ciphertextSample(ciphertext);
    const key = mlsExpandWithLabel(senderDataSecret, "key", sample, MLS_AEAD_KEY_LENGTH);
    try {
        return {
            key,
            nonce: mlsExpandWithLabel(senderDataSecret, "nonce", sample, MLS_AEAD_NONCE_LENGTH),
        };
    } catch (error: unknown) {
        zeroBytes(key);
        throw error;
    } finally {
        zeroBytes(sample);
    }
}

function guardedNonce(generationKey: MlsGenerationKey, reuseGuard: Uint8Array): Uint8Array {
    if (reuseGuard.length !== REUSE_GUARD_BYTES) {
        throw new Error("Invalid MLS reuse guard");
    }
    const nonce = generationKey.nonce.slice();
    for (let index = 0; index < reuseGuard.length; index += 1) {
        nonce[index] = (nonce[index] ?? 0) ^ (reuseGuard[index] ?? 0);
    }
    return nonce;
}

/** Sign and encrypt one RFC 9420 application PrivateMessage. */
export function sealMlsApplicationMessage(options: SealMlsApplicationMessageOptions): Uint8Array {
    const authenticatedData = options.authenticatedData?.slice() ?? new Uint8Array();
    const paddingBytes = options.paddingBytes ?? 0;
    if (
        authenticatedData.length > MAXIMUM_MLS_AUTHENTICATED_DATA_BYTES ||
        options.applicationData.length > MAXIMUM_MLS_APPLICATION_BYTES
    ) {
        throw new Error("MLS application message is too large");
    }
    // Validation is shared with the exact GroupContext encoder.
    encodeMlsGroupContext(options.context);
    const reuseGuard = randomBytes(REUSE_GUARD_BYTES);
    let generationKey: MlsGenerationKey | undefined;
    let privateContent: Uint8Array | undefined;
    try {
        const signature = mlsSignWithLabel(
            options.signingSecretKey,
            "FramedContentTBS",
            encodeFramedContentTbs({ ...options, authenticatedData }),
        );
        privateContent = encodePrivateContent(options.applicationData, signature, paddingBytes);
        generationKey = options.secretTree.next(options.sender, "application");
        const generation = generationKey.generation;
        let nonce: Uint8Array | undefined;
        let ciphertext: Uint8Array;
        try {
            nonce = guardedNonce(generationKey, reuseGuard);
            ciphertext = mlsAeadSeal(
                generationKey.key,
                nonce,
                privateContentAad({
                    groupId: options.context.groupId,
                    epoch: options.context.epoch,
                    authenticatedData,
                }),
                privateContent,
            );
        } finally {
            if (nonce !== undefined) {
                zeroBytes(nonce);
            }
        }
        destroyMlsGenerationKey(generationKey);
        generationKey = undefined;
        zeroBytes(privateContent);
        privateContent = undefined;

        const senderKeys = deriveSenderDataKeyAndNonce(options.senderDataSecret, ciphertext);
        let senderDataPlaintext: Uint8Array | undefined;
        try {
            senderDataPlaintext = encodeSenderData({
                sender: options.sender,
                generation,
                reuseGuard,
            });
            const message: MlsPrivateMessage = {
                groupId: options.context.groupId,
                epoch: options.context.epoch,
                authenticatedData,
                encryptedSenderData: mlsAeadSeal(
                    senderKeys.key,
                    senderKeys.nonce,
                    senderDataAad({
                        groupId: options.context.groupId,
                        epoch: options.context.epoch,
                    }),
                    senderDataPlaintext,
                ),
                ciphertext,
            };
            return encodeMlsPrivateMessage(message);
        } finally {
            zeroBytes(senderKeys.key);
            zeroBytes(senderKeys.nonce);
            if (senderDataPlaintext !== undefined) {
                zeroBytes(senderDataPlaintext);
            }
        }
    } finally {
        if (generationKey !== undefined) {
            destroyMlsGenerationKey(generationKey);
        }
        if (privateContent !== undefined) {
            zeroBytes(privateContent);
        }
        zeroBytes(reuseGuard);
    }
}

/** Authenticate and decrypt one RFC 9420 application PrivateMessage. */
export function openMlsApplicationMessage(
    options: OpenMlsApplicationMessageOptions,
): OpenedMlsApplicationMessage {
    const message = decodeMlsPrivateMessage(options.message);
    if (
        message.epoch !== options.context.epoch ||
        !equalBytes(message.groupId, options.context.groupId)
    ) {
        throw new Error("MLS PrivateMessage belongs to another group or epoch");
    }
    encodeMlsGroupContext(options.context);

    const senderKeys = deriveSenderDataKeyAndNonce(options.senderDataSecret, message.ciphertext);
    let senderDataPlaintext: Uint8Array;
    try {
        senderDataPlaintext = mlsAeadOpen(
            senderKeys.key,
            senderKeys.nonce,
            senderDataAad(message),
            message.encryptedSenderData,
        );
    } finally {
        zeroBytes(senderKeys.key);
        zeroBytes(senderKeys.nonce);
    }
    let senderData: SenderData;
    try {
        senderData = decodeSenderData(senderDataPlaintext);
    } finally {
        zeroBytes(senderDataPlaintext);
    }

    try {
        return options.secretTree.use(
            senderData.sender,
            "application",
            senderData.generation,
            (generationKey) => {
                const nonce = guardedNonce(generationKey, senderData.reuseGuard);
                let plaintext: Uint8Array;
                try {
                    plaintext = mlsAeadOpen(
                        generationKey.key,
                        nonce,
                        privateContentAad(message),
                        message.ciphertext,
                    );
                } finally {
                    zeroBytes(nonce);
                }
                try {
                    const privateContent = decodePrivateContent(plaintext);
                    const signatureKey = options.signatureKeyFor(senderData.sender);
                    if (
                        signatureKey === undefined ||
                        signatureKey.length !== 32 ||
                        !mlsVerifyWithLabel(
                            signatureKey,
                            "FramedContentTBS",
                            encodeFramedContentTbs({
                                context: options.context,
                                sender: senderData.sender,
                                authenticatedData: message.authenticatedData,
                                applicationData: privateContent.applicationData,
                            }),
                            privateContent.signature,
                        )
                    ) {
                        throw new Error("Invalid MLS application signature");
                    }
                    return {
                        sender: senderData.sender,
                        generation: senderData.generation,
                        authenticatedData: message.authenticatedData,
                        applicationData: privateContent.applicationData,
                    };
                } finally {
                    zeroBytes(plaintext);
                }
            },
        );
    } finally {
        zeroBytes(senderData.reuseGuard);
    }
}
