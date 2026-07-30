import { concatBytes, equalBytes, hashBytes } from "@slopus/murmur";
import {
    MLS_CIPHER_SUITE,
    MLS_HASH_LENGTH,
    MLS_PROTOCOL_VERSION,
    mlsMac,
    mlsVerifyMac,
} from "../cipherSuite/index.js";
import { decodeVarint, encodeOpaqueV, encodeUint16, encodeUint64 } from "../encoding/index.js";
import type { MlsGroupContext } from "./types.js";

export type { MlsGroupContext } from "./types.js";

const EMPTY_EXTENSIONS = new Uint8Array();
const MAXIMUM_GROUP_ID_BYTES = 255;

class Reader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS GroupContext");
        }
        return this.bytes[this.#offset++] ?? 0;
    }

    readUint16(): number {
        return (this.readUint8() << 8) | this.readUint8();
    }

    readUint64(): bigint {
        let value = 0n;
        for (let index = 0; index < 8; index += 1) {
            value = (value << 8n) | BigInt(this.readUint8());
        }
        return value;
    }

    readOpaqueV(maximumBytes: number): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS GroupContext vector is too large");
        }
        const length = Number(decoded.value);
        if (this.#offset + length > this.bytes.length) {
            throw new Error("Truncated MLS GroupContext vector");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    ensureEnd(): void {
        if (this.#offset !== this.bytes.length) {
            throw new Error("Trailing bytes in MLS GroupContext");
        }
    }
}

function validateGroupContext(context: MlsGroupContext): void {
    if (
        context.groupId.length === 0 ||
        context.groupId.length > MAXIMUM_GROUP_ID_BYTES ||
        context.epoch < 0n ||
        context.epoch > 0xffff_ffff_ffff_ffffn ||
        context.treeHash.length !== MLS_HASH_LENGTH ||
        (context.confirmedTranscriptHash.length !== 0 &&
            context.confirmedTranscriptHash.length !== MLS_HASH_LENGTH)
    ) {
        throw new Error("Invalid MLS GroupContext");
    }
}

/** Encode the exact RFC 9420 GroupContext structure for the extension-free profile. */
export function encodeMlsGroupContext(context: MlsGroupContext): Uint8Array {
    validateGroupContext(context);
    return concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_CIPHER_SUITE),
        encodeOpaqueV(context.groupId),
        encodeUint64(context.epoch),
        encodeOpaqueV(context.treeHash),
        encodeOpaqueV(context.confirmedTranscriptHash),
        encodeOpaqueV(EMPTY_EXTENSIONS),
    );
}

/** Decode the extension-free RFC 9420 GroupContext profile. */
export function decodeMlsGroupContext(bytes: Uint8Array): MlsGroupContext {
    const reader = new Reader(bytes);
    if (reader.readUint16() !== MLS_PROTOCOL_VERSION || reader.readUint16() !== MLS_CIPHER_SUITE) {
        throw new Error("Unsupported MLS GroupContext profile");
    }
    const context: MlsGroupContext = {
        groupId: reader.readOpaqueV(MAXIMUM_GROUP_ID_BYTES),
        epoch: reader.readUint64(),
        treeHash: reader.readOpaqueV(MLS_HASH_LENGTH),
        confirmedTranscriptHash: reader.readOpaqueV(MLS_HASH_LENGTH),
    };
    if (reader.readOpaqueV(0).length !== 0) {
        throw new Error("Unsupported MLS GroupContext extension");
    }
    reader.ensureEnd();
    validateGroupContext(context);
    if ((context.epoch === 0n) !== (context.confirmedTranscriptHash.length === 0)) {
        throw new Error("Invalid final MLS GroupContext transcript");
    }
    return context;
}

/**
 * Initialize the RFC 9420 confirmed transcript hash for a new group.
 *
 * The initial hash has no preceding interim transcript hash.
 */
export function initializeConfirmedTranscriptHash(
    confirmedTranscriptInput: Uint8Array,
): Uint8Array {
    return hashBytes(confirmedTranscriptInput);
}

/**
 * Update the RFC 9420 confirmed transcript hash.
 *
 * `confirmedTranscriptInput` is the exact encoded ConfirmedTranscriptHashInput
 * (wire format, FramedContent, and signature) for the accepted Commit.
 */
export function updateConfirmedTranscriptHash(
    interimTranscriptHash: Uint8Array,
    confirmedTranscriptInput: Uint8Array,
): Uint8Array {
    if (interimTranscriptHash.length !== MLS_HASH_LENGTH) {
        throw new Error("Invalid MLS interim transcript hash");
    }
    return hashBytes(concatBytes(interimTranscriptHash, confirmedTranscriptInput));
}

/** Update the RFC 9420 interim transcript hash after confirmation. */
export function updateInterimTranscriptHash(
    confirmedTranscriptHash: Uint8Array,
    confirmationTag: Uint8Array,
): Uint8Array {
    if (
        (confirmedTranscriptHash.length !== 0 &&
            confirmedTranscriptHash.length !== MLS_HASH_LENGTH) ||
        confirmationTag.length !== MLS_HASH_LENGTH
    ) {
        throw new Error("Invalid MLS transcript confirmation");
    }
    return hashBytes(concatBytes(confirmedTranscriptHash, encodeOpaqueV(confirmationTag)));
}

/** Compute the RFC 9420 confirmation tag for an epoch. */
export function createMlsConfirmationTag(
    confirmationKey: Uint8Array,
    confirmedTranscriptHash: Uint8Array,
): Uint8Array {
    if (
        confirmationKey.length !== MLS_HASH_LENGTH ||
        (confirmedTranscriptHash.length !== 0 && confirmedTranscriptHash.length !== MLS_HASH_LENGTH)
    ) {
        throw new Error("Invalid MLS confirmation input");
    }
    return mlsMac(confirmationKey, confirmedTranscriptHash);
}

/** Verify an RFC 9420 confirmation tag. */
export function verifyMlsConfirmationTag(
    confirmationKey: Uint8Array,
    confirmedTranscriptHash: Uint8Array,
    confirmationTag: Uint8Array,
): boolean {
    if (
        confirmationKey.length !== MLS_HASH_LENGTH ||
        (confirmedTranscriptHash.length !== 0 &&
            confirmedTranscriptHash.length !== MLS_HASH_LENGTH) ||
        confirmationTag.length !== MLS_HASH_LENGTH
    ) {
        return false;
    }
    return mlsVerifyMac(confirmationKey, confirmedTranscriptHash, confirmationTag);
}

/** Compare two GroupContexts without timing-dependent hash comparisons. */
export function equalMlsGroupContext(left: MlsGroupContext, right: MlsGroupContext): boolean {
    return (
        left.epoch === right.epoch &&
        equalBytes(left.groupId, right.groupId) &&
        equalBytes(left.treeHash, right.treeHash) &&
        equalBytes(left.confirmedTranscriptHash, right.confirmedTranscriptHash)
    );
}
