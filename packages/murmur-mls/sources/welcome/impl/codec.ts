import { concatBytes } from "@slopus/murmur";
import {
    MLS_CIPHER_SUITE,
    MLS_HASH_LENGTH,
    MLS_PROTOCOL_VERSION,
} from "../../cipherSuite/index.js";
import { decodeVarint, encodeOpaqueV, encodeUint16, encodeUint32 } from "../../encoding/index.js";
import { decodeMlsGroupContext, encodeMlsGroupContext } from "../../groupContext/index.js";
import type { MlsEncryptedGroupSecrets, MlsGroupInfo, MlsWelcome } from "../types.js";

const MAXIMUM_WELCOME_BYTES = 16 * 1024 * 1024;
const MAXIMUM_WELCOME_MEMBERS = 1_024;
const MAXIMUM_HPKE_CIPHERTEXT_BYTES = 2 * 1024 * 1024;
const MAXIMUM_GROUP_INFO_BYTES = 2 * 1024 * 1024;
const MAXIMUM_GROUP_CONTEXT_BYTES = 4 * 1024;
const MAXIMUM_SIGNATURE_BYTES = 64;
const MLS_WIRE_FORMAT_WELCOME = 3;

export class WelcomeReader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    get remaining(): number {
        return this.bytes.length - this.#offset;
    }

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS Welcome");
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

    readBytes(length: number): Uint8Array {
        if (
            !Number.isSafeInteger(length) ||
            length < 0 ||
            this.#offset + length > this.bytes.length
        ) {
            throw new Error("Truncated MLS Welcome bytes");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    readOpaqueV(maximumBytes: number): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS Welcome vector is too large");
        }
        return this.readBytes(Number(decoded.value));
    }

    ensureEnd(): void {
        if (this.remaining !== 0) {
            throw new Error("Trailing bytes in MLS Welcome");
        }
    }
}

function encodeEncryptedGroupSecrets(value: MlsEncryptedGroupSecrets): Uint8Array {
    if (
        value.newMember.length !== MLS_HASH_LENGTH ||
        value.encryptedGroupSecrets.encapsulatedKey.length !== 32 ||
        value.encryptedGroupSecrets.ciphertext.length > MAXIMUM_HPKE_CIPHERTEXT_BYTES
    ) {
        throw new Error("Invalid MLS EncryptedGroupSecrets");
    }
    return concatBytes(
        encodeOpaqueV(value.newMember),
        encodeOpaqueV(value.encryptedGroupSecrets.encapsulatedKey),
        encodeOpaqueV(value.encryptedGroupSecrets.ciphertext),
    );
}

function decodeEncryptedGroupSecrets(reader: WelcomeReader): MlsEncryptedGroupSecrets {
    return {
        newMember: reader.readOpaqueV(MLS_HASH_LENGTH),
        encryptedGroupSecrets: {
            encapsulatedKey: reader.readOpaqueV(32),
            ciphertext: reader.readOpaqueV(MAXIMUM_HPKE_CIPHERTEXT_BYTES),
        },
    };
}

/** Encode an RFC 9420 Welcome for suite 0x0001. */
export function encodeMlsWelcome(welcome: MlsWelcome): Uint8Array {
    if (
        welcome.secrets.length === 0 ||
        welcome.secrets.length > MAXIMUM_WELCOME_MEMBERS ||
        welcome.encryptedGroupInfo.length > MAXIMUM_GROUP_INFO_BYTES
    ) {
        throw new Error("Invalid MLS Welcome");
    }
    const encoded = concatBytes(
        encodeUint16(MLS_PROTOCOL_VERSION),
        encodeUint16(MLS_WIRE_FORMAT_WELCOME),
        encodeUint16(MLS_CIPHER_SUITE),
        encodeOpaqueV(concatBytes(...welcome.secrets.map(encodeEncryptedGroupSecrets))),
        encodeOpaqueV(welcome.encryptedGroupInfo),
    );
    if (encoded.length > MAXIMUM_WELCOME_BYTES) {
        throw new Error("MLS Welcome is too large");
    }
    return encoded;
}

/** Decode an RFC 9420 Welcome for suite 0x0001. */
export function decodeMlsWelcome(bytes: Uint8Array): MlsWelcome {
    if (bytes.length > MAXIMUM_WELCOME_BYTES) {
        throw new Error("MLS Welcome is too large");
    }
    const reader = new WelcomeReader(bytes);
    if (
        reader.readUint16() !== MLS_PROTOCOL_VERSION ||
        reader.readUint16() !== MLS_WIRE_FORMAT_WELCOME ||
        reader.readUint16() !== MLS_CIPHER_SUITE
    ) {
        throw new Error("Unsupported MLS Welcome version, wire format, or cipher suite");
    }
    const secretsReader = new WelcomeReader(reader.readOpaqueV(MAXIMUM_WELCOME_BYTES));
    const secrets: MlsEncryptedGroupSecrets[] = [];
    while (secretsReader.remaining > 0) {
        if (secrets.length >= MAXIMUM_WELCOME_MEMBERS) {
            throw new Error("MLS Welcome has too many members");
        }
        secrets.push(decodeEncryptedGroupSecrets(secretsReader));
    }
    const welcome: MlsWelcome = {
        secrets,
        encryptedGroupInfo: reader.readOpaqueV(MAXIMUM_GROUP_INFO_BYTES),
    };
    reader.ensureEnd();
    encodeMlsWelcome(welcome);
    return welcome;
}

/** Fields covered by the RFC 9420 GroupInfoTBS signature. */
export function encodeMlsGroupInfoTbs(groupInfo: Omit<MlsGroupInfo, "signature">): Uint8Array {
    if (
        groupInfo.confirmationTag.length !== MLS_HASH_LENGTH ||
        !Number.isSafeInteger(groupInfo.signer) ||
        groupInfo.signer < 0 ||
        groupInfo.signer > 0xffff_ffff
    ) {
        throw new Error("Invalid MLS GroupInfo");
    }
    return concatBytes(
        encodeMlsGroupContext(groupInfo.context),
        encodeOpaqueV(new Uint8Array()),
        encodeOpaqueV(groupInfo.confirmationTag),
        encodeUint32(groupInfo.signer),
    );
}

/** Encode the extension-free RFC 9420 GroupInfo profile. */
export function encodeMlsGroupInfo(groupInfo: MlsGroupInfo): Uint8Array {
    if (groupInfo.signature.length !== MAXIMUM_SIGNATURE_BYTES) {
        throw new Error("Invalid MLS GroupInfo signature");
    }
    return concatBytes(encodeMlsGroupInfoTbs(groupInfo), encodeOpaqueV(groupInfo.signature));
}

/** Decode the extension-free RFC 9420 GroupInfo profile. */
export function decodeMlsGroupInfo(bytes: Uint8Array): MlsGroupInfo {
    const reader = new WelcomeReader(bytes);
    const version = reader.readUint16();
    const cipherSuite = reader.readUint16();
    const contextBytesStart = reader.readOpaqueV(255);
    // GroupContext is not nested on the wire. Reconstruct its exact encoding
    // from sequential fields so its shared strict decoder remains authoritative.
    const epoch = reader.readBytes(8);
    const treeHash = reader.readOpaqueV(MLS_HASH_LENGTH);
    const transcriptHash = reader.readOpaqueV(MLS_HASH_LENGTH);
    const contextExtensions = reader.readOpaqueV(0);
    const contextBytes = concatBytes(
        encodeUint16(version),
        encodeUint16(cipherSuite),
        encodeOpaqueV(contextBytesStart),
        epoch,
        encodeOpaqueV(treeHash),
        encodeOpaqueV(transcriptHash),
        encodeOpaqueV(contextExtensions),
    );
    if (contextBytes.length > MAXIMUM_GROUP_CONTEXT_BYTES) {
        throw new Error("MLS GroupContext is too large");
    }
    const context = decodeMlsGroupContext(contextBytes);
    if (reader.readOpaqueV(0).length !== 0) {
        throw new Error("Unsupported MLS GroupInfo extension");
    }
    const groupInfo: MlsGroupInfo = {
        context,
        confirmationTag: reader.readOpaqueV(MLS_HASH_LENGTH),
        signer: reader.readUint32(),
        signature: reader.readOpaqueV(MAXIMUM_SIGNATURE_BYTES),
    };
    reader.ensureEnd();
    encodeMlsGroupInfo(groupInfo);
    return groupInfo;
}
