import { concatBytes } from "@murmur/core";
import { MLS_HASH_LENGTH, MLS_PROTOCOL_VERSION } from "../../cipherSuite/index.js";
import {
    decodeVarint,
    encodeOpaqueV,
    encodeUint16,
    encodeUint32,
    encodeUint64,
} from "../../encoding/index.js";
import { encodeMlsGroupContext, type MlsGroupContext } from "../../groupContext/index.js";
import { decodeMlsKeyPackageFromReader, encodeMlsKeyPackage } from "../../keyPackage/impl/codec.js";
import type { MlsAddCommitMessage } from "../types.js";

export const MLS_WIRE_FORMAT_PUBLIC_MESSAGE = 1;
const MLS_SENDER_TYPE_MEMBER = 1;
const MLS_CONTENT_TYPE_COMMIT = 3;
const MLS_PROPOSAL_OR_REF_INLINE = 1;
const MLS_PROPOSAL_TYPE_ADD = 1;
const MAXIMUM_COMMIT_BYTES = 16 * 1024 * 1024;
const MAXIMUM_AUTHENTICATED_DATA_BYTES = 1024 * 1024;
const MAXIMUM_GROUP_ID_BYTES = 255;
const MAXIMUM_ADDITIONS = 1_024;
const SIGNATURE_BYTES = 64;

class CommitReader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    get remaining(): number {
        return this.bytes.length - this.#offset;
    }

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS Commit");
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
            throw new Error("Truncated MLS Commit bytes");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    readOpaqueV(maximumBytes: number = MAXIMUM_COMMIT_BYTES): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS Commit vector is too large");
        }
        return this.readBytes(Number(decoded.value));
    }

    ensureEnd(): void {
        if (this.remaining !== 0) {
            throw new Error("Trailing bytes in MLS Commit");
        }
    }
}

function validateMessage(message: MlsAddCommitMessage): void {
    if (
        message.groupId.length === 0 ||
        message.groupId.length > MAXIMUM_GROUP_ID_BYTES ||
        message.epoch < 0n ||
        message.epoch > 0xffff_ffff_ffff_ffffn ||
        !Number.isSafeInteger(message.sender) ||
        message.sender < 0 ||
        message.sender > 0xffff_ffff ||
        message.authenticatedData.length > MAXIMUM_AUTHENTICATED_DATA_BYTES ||
        message.additions.length === 0 ||
        message.additions.length > MAXIMUM_ADDITIONS ||
        message.signature.length !== SIGNATURE_BYTES ||
        message.confirmationTag.length !== MLS_HASH_LENGTH ||
        message.membershipTag.length !== MLS_HASH_LENGTH
    ) {
        throw new Error("Invalid MLS add Commit");
    }
}

function encodeProposal(keyPackage: MlsAddCommitMessage["additions"][number]): Uint8Array {
    return concatBytes(
        new Uint8Array([MLS_PROPOSAL_OR_REF_INLINE]),
        encodeUint16(MLS_PROPOSAL_TYPE_ADD),
        encodeMlsKeyPackage(keyPackage),
    );
}

function encodeCommitContent(message: MlsAddCommitMessage): Uint8Array {
    return concatBytes(
        encodeOpaqueV(concatBytes(...message.additions.map(encodeProposal))),
        new Uint8Array([0]),
    );
}

/** Exact FramedContent bytes carried by the add-only PublicMessage. */
export function encodeMlsAddCommitFramedContent(message: MlsAddCommitMessage): Uint8Array {
    validateMessage(message);
    return concatBytes(
        encodeOpaqueV(message.groupId),
        encodeUint64(message.epoch),
        new Uint8Array([MLS_SENDER_TYPE_MEMBER]),
        encodeUint32(message.sender),
        encodeOpaqueV(message.authenticatedData),
        new Uint8Array([MLS_CONTENT_TYPE_COMMIT]),
        encodeCommitContent(message),
    );
}

/** Exact RFC FramedContentTBS for a member Commit. */
export function encodeMlsAddCommitTbs(
    message: MlsAddCommitMessage,
    context: MlsGroupContext,
): Uint8Array {
    return concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_PUBLIC_MESSAGE),
        encodeMlsAddCommitFramedContent(message),
        encodeMlsGroupContext(context),
    );
}

/** Exact RFC ConfirmedTranscriptHashInput for this Commit. */
export function encodeMlsAddCommitConfirmedTranscriptInput(
    message: MlsAddCommitMessage,
): Uint8Array {
    return concatBytes(
        encodeUint16(MLS_WIRE_FORMAT_PUBLIC_MESSAGE),
        encodeMlsAddCommitFramedContent(message),
        encodeOpaqueV(message.signature),
    );
}

/** Exact RFC AuthenticatedContentTBM covered by the membership tag. */
export function encodeMlsAddCommitTbm(
    message: MlsAddCommitMessage,
    context: MlsGroupContext,
): Uint8Array {
    return concatBytes(
        encodeMlsAddCommitTbs(message, context),
        encodeOpaqueV(message.signature),
        new Uint8Array([1]),
        encodeOpaqueV(message.confirmationTag),
    );
}

/** Encode a full RFC 9420 MLSMessage containing an add-only PublicMessage Commit. */
export function encodeMlsAddCommit(message: MlsAddCommitMessage): Uint8Array {
    const encoded = concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_PUBLIC_MESSAGE),
        encodeMlsAddCommitFramedContent(message),
        encodeOpaqueV(message.signature),
        new Uint8Array([1]),
        encodeOpaqueV(message.confirmationTag),
        encodeOpaqueV(message.membershipTag),
    );
    if (encoded.length > MAXIMUM_COMMIT_BYTES) {
        throw new Error("MLS Commit is too large");
    }
    return encoded;
}

function decodeAdditions(
    reader: CommitReader,
): readonly MlsAddCommitMessage["additions"][number][] {
    const proposals = new CommitReader(reader.readOpaqueV(MAXIMUM_COMMIT_BYTES));
    const additions: MlsAddCommitMessage["additions"][number][] = [];
    while (proposals.remaining > 0) {
        if (additions.length >= MAXIMUM_ADDITIONS) {
            throw new Error("MLS Commit has too many proposals");
        }
        if (
            proposals.readUint8() !== MLS_PROPOSAL_OR_REF_INLINE ||
            proposals.readUint16() !== MLS_PROPOSAL_TYPE_ADD
        ) {
            throw new Error("Unsupported MLS Commit proposal");
        }
        additions.push(decodeMlsKeyPackageFromReader(proposals));
    }
    if (reader.readUint8() !== 0) {
        throw new Error("Add-only MLS Commit cannot contain an UpdatePath");
    }
    return additions;
}

/** Decode the supported RFC 9420 add-only PublicMessage Commit profile. */
export function decodeMlsAddCommit(bytes: Uint8Array): MlsAddCommitMessage {
    if (bytes.length > MAXIMUM_COMMIT_BYTES) {
        throw new Error("MLS Commit is too large");
    }
    const reader = new CommitReader(bytes);
    if (
        reader.readUint16() !== MLS_PROTOCOL_VERSION ||
        reader.readUint16() !== MLS_WIRE_FORMAT_PUBLIC_MESSAGE
    ) {
        throw new Error("Unsupported MLS message version or wire format");
    }
    const groupId = reader.readOpaqueV(MAXIMUM_GROUP_ID_BYTES);
    const epoch = reader.readUint64();
    if (reader.readUint8() !== MLS_SENDER_TYPE_MEMBER) {
        throw new Error("Expected an MLS member sender");
    }
    const sender = reader.readUint32();
    const authenticatedData = reader.readOpaqueV(MAXIMUM_AUTHENTICATED_DATA_BYTES);
    if (reader.readUint8() !== MLS_CONTENT_TYPE_COMMIT) {
        throw new Error("Expected MLS Commit content");
    }
    const additions = decodeAdditions(reader);
    const signature = reader.readOpaqueV(SIGNATURE_BYTES);
    if (reader.readUint8() !== 1) {
        throw new Error("MLS Commit requires a confirmation tag");
    }
    const message: MlsAddCommitMessage = {
        groupId,
        epoch,
        sender,
        authenticatedData,
        additions,
        signature,
        confirmationTag: reader.readOpaqueV(MLS_HASH_LENGTH),
        membershipTag: reader.readOpaqueV(MLS_HASH_LENGTH),
    };
    reader.ensureEnd();
    validateMessage(message);
    return message;
}
