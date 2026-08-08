import { concatBytes } from "../../internal.js";
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
import {
    decodeMlsUpdatePathFromReader,
    encodeMlsUpdatePath,
    type MlsUpdatePathReader,
} from "../../updatePath/index.js";
import type { MlsTreeCommitMessage, MlsTreeCommitProposal } from "../types.js";

const MLS_WIRE_FORMAT_PUBLIC_MESSAGE = 1;
const MLS_SENDER_TYPE_MEMBER = 1;
const MLS_CONTENT_TYPE_COMMIT = 3;
const MLS_PROPOSAL_OR_REF_INLINE = 1;
const MLS_PROPOSAL_TYPE_ADD = 1;
const MLS_PROPOSAL_TYPE_REMOVE = 3;
const MAXIMUM_COMMIT_BYTES = 16 * 1024 * 1024;
const MAXIMUM_AUTHENTICATED_DATA_BYTES = 1024 * 1024;
const MAXIMUM_GROUP_ID_BYTES = 255;
const MAXIMUM_PROPOSALS = 1_024;
const SIGNATURE_BYTES = 64;

class TreeCommitReader implements MlsUpdatePathReader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    get remaining(): number {
        return this.bytes.length - this.#offset;
    }

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS TreeKEM Commit");
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

    readOpaqueV(maximumBytes: number = MAXIMUM_COMMIT_BYTES): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS TreeKEM Commit vector is too large");
        }
        const length = Number(decoded.value);
        if (this.#offset + length > this.bytes.length) {
            throw new Error("Truncated MLS TreeKEM Commit vector");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    ensureEnd(): void {
        if (this.remaining !== 0) {
            throw new Error("Trailing bytes in MLS TreeKEM Commit");
        }
    }
}

function validateMessage(message: MlsTreeCommitMessage): void {
    if (
        message.groupId.length === 0 ||
        message.groupId.length > MAXIMUM_GROUP_ID_BYTES ||
        message.epoch < 0n ||
        message.epoch > 0xffff_ffff_ffff_ffffn ||
        !Number.isSafeInteger(message.sender) ||
        message.sender < 0 ||
        message.sender > 0xffff_ffff ||
        message.authenticatedData.length > MAXIMUM_AUTHENTICATED_DATA_BYTES ||
        message.proposals.length > MAXIMUM_PROPOSALS ||
        message.signature.length !== SIGNATURE_BYTES ||
        message.confirmationTag.length !== MLS_HASH_LENGTH ||
        message.membershipTag.length !== MLS_HASH_LENGTH
    ) {
        throw new Error("Invalid MLS TreeKEM Commit");
    }
}

function encodeProposal(proposal: MlsTreeCommitProposal): Uint8Array {
    return proposal.type === "add"
        ? concatBytes(
              new Uint8Array([MLS_PROPOSAL_OR_REF_INLINE]),
              encodeUint16(MLS_PROPOSAL_TYPE_ADD),
              encodeMlsKeyPackage(proposal.keyPackage),
          )
        : concatBytes(
              new Uint8Array([MLS_PROPOSAL_OR_REF_INLINE]),
              encodeUint16(MLS_PROPOSAL_TYPE_REMOVE),
              encodeUint32(proposal.removed),
          );
}

function encodeCommitContent(message: MlsTreeCommitMessage): Uint8Array {
    return concatBytes(
        encodeOpaqueV(concatBytes(...message.proposals.map(encodeProposal))),
        new Uint8Array([1]),
        encodeMlsUpdatePath(message.path, {
            groupId: message.groupId,
            leafIndex: message.sender,
        }),
    );
}

/** Exact FramedContent bytes for a full Add/Remove TreeKEM Commit. */
export function encodeMlsTreeCommitFramedContent(message: MlsTreeCommitMessage): Uint8Array {
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

/** Exact FramedContentTBS for a full member Commit. */
export function encodeMlsTreeCommitTbs(
    message: MlsTreeCommitMessage,
    context: MlsGroupContext,
): Uint8Array {
    return concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_PUBLIC_MESSAGE),
        encodeMlsTreeCommitFramedContent(message),
        encodeMlsGroupContext(context),
    );
}

/** Exact ConfirmedTranscriptHashInput for a full Commit. */
export function encodeMlsTreeCommitConfirmedTranscriptInput(
    message: MlsTreeCommitMessage,
): Uint8Array {
    return concatBytes(
        encodeUint16(MLS_WIRE_FORMAT_PUBLIC_MESSAGE),
        encodeMlsTreeCommitFramedContent(message),
        encodeOpaqueV(message.signature),
    );
}

/** Exact AuthenticatedContentTBM for a full Commit. */
export function encodeMlsTreeCommitTbm(
    message: MlsTreeCommitMessage,
    context: MlsGroupContext,
): Uint8Array {
    return concatBytes(
        encodeMlsTreeCommitTbs(message, context),
        encodeOpaqueV(message.signature),
        new Uint8Array([1]),
        encodeOpaqueV(message.confirmationTag),
    );
}

/** Encode a full RFC MLSMessage/PublicMessage TreeKEM Commit. */
export function encodeMlsTreeCommit(message: MlsTreeCommitMessage): Uint8Array {
    const encoded = concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_PUBLIC_MESSAGE),
        encodeMlsTreeCommitFramedContent(message),
        encodeOpaqueV(message.signature),
        new Uint8Array([1]),
        encodeOpaqueV(message.confirmationTag),
        encodeOpaqueV(message.membershipTag),
    );
    if (encoded.length > MAXIMUM_COMMIT_BYTES) {
        throw new Error("MLS TreeKEM Commit is too large");
    }
    return encoded;
}

function decodeProposals(reader: TreeCommitReader): readonly MlsTreeCommitProposal[] {
    const proposalsReader = new TreeCommitReader(reader.readOpaqueV(MAXIMUM_COMMIT_BYTES));
    const proposals: MlsTreeCommitProposal[] = [];
    while (proposalsReader.remaining > 0) {
        if (
            proposals.length >= MAXIMUM_PROPOSALS ||
            proposalsReader.readUint8() !== MLS_PROPOSAL_OR_REF_INLINE
        ) {
            throw new Error("Invalid MLS TreeKEM Commit proposal list");
        }
        const type = proposalsReader.readUint16();
        if (type === MLS_PROPOSAL_TYPE_ADD) {
            proposals.push({
                type: "add",
                keyPackage: decodeMlsKeyPackageFromReader(proposalsReader),
            });
        } else if (type === MLS_PROPOSAL_TYPE_REMOVE) {
            proposals.push({ type: "remove", removed: proposalsReader.readUint32() });
        } else {
            throw new Error("Unsupported MLS TreeKEM Commit proposal");
        }
    }
    return proposals;
}

/** Decode the full Add/Remove TreeKEM Commit profile. */
export function decodeMlsTreeCommit(bytes: Uint8Array): MlsTreeCommitMessage {
    if (bytes.length > MAXIMUM_COMMIT_BYTES) {
        throw new Error("MLS TreeKEM Commit is too large");
    }
    const reader = new TreeCommitReader(bytes);
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
    const proposals = decodeProposals(reader);
    if (reader.readUint8() !== 1) {
        throw new Error("Full MLS TreeKEM Commit requires an UpdatePath");
    }
    const path = decodeMlsUpdatePathFromReader(reader);
    const signature = reader.readOpaqueV(SIGNATURE_BYTES);
    if (reader.readUint8() !== 1) {
        throw new Error("MLS TreeKEM Commit requires a confirmation tag");
    }
    const message: MlsTreeCommitMessage = {
        groupId,
        epoch,
        sender,
        authenticatedData,
        proposals,
        path,
        signature,
        confirmationTag: reader.readOpaqueV(MLS_HASH_LENGTH),
        membershipTag: reader.readOpaqueV(MLS_HASH_LENGTH),
    };
    reader.ensureEnd();
    validateMessage(message);
    return message;
}
