import { concatBytes } from "@murmur/core";
import { MLS_CIPHER_SUITE, MLS_PROTOCOL_VERSION } from "../../cipherSuite/index.js";
import { decodeVarint, encodeOpaqueV, encodeUint16, encodeUint64 } from "../../encoding/index.js";
import type { MlsBasicCredential, MlsKeyPackage, MlsKeyPackageLeafNode } from "../types.js";

const CREDENTIAL_TYPE_BASIC = 1;
const LEAF_NODE_SOURCE_KEY_PACKAGE = 1;
const SUPPORTED_PROPOSALS = [1, 2, 3] as const;

export interface MlsKeyPackageReader {
    readUint8(): number;
    readUint16(): number;
    readUint64(): bigint;
    readOpaqueV(): Uint8Array;
}

class Reader implements MlsKeyPackageReader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS structure");
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

    readOpaqueV(): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error("MLS vector is too large");
        }
        const length = Number(decoded.value);
        if (this.#offset + length > this.bytes.length) {
            throw new Error("Truncated MLS vector");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }

    ensureEnd(): void {
        if (this.#offset !== this.bytes.length) {
            throw new Error("Trailing bytes in MLS structure");
        }
    }
}

function encodeUint16Vector(values: readonly number[]): Uint8Array {
    return encodeOpaqueV(concatBytes(...values.map((value) => encodeUint16(value))));
}

function decodeUint16Vector(reader: MlsKeyPackageReader): readonly number[] {
    const encoded = reader.readOpaqueV();
    if (encoded.length % 2 !== 0) {
        throw new Error("Invalid uint16 MLS vector");
    }
    const result: number[] = [];
    for (let index = 0; index < encoded.length; index += 2) {
        result.push(((encoded[index] ?? 0) << 8) | (encoded[index + 1] ?? 0));
    }
    return result;
}

function encodeCredential(credential: MlsBasicCredential): Uint8Array {
    return concatBytes(encodeUint16(CREDENTIAL_TYPE_BASIC), encodeOpaqueV(credential.identity));
}

function decodeCredential(reader: MlsKeyPackageReader): MlsBasicCredential {
    if (reader.readUint16() !== CREDENTIAL_TYPE_BASIC) {
        throw new Error("Unsupported MLS credential type");
    }
    return { identity: reader.readOpaqueV() };
}

function encodeCapabilities(): Uint8Array {
    return concatBytes(
        encodeUint16Vector([MLS_PROTOCOL_VERSION]),
        encodeUint16Vector([MLS_CIPHER_SUITE]),
        encodeUint16Vector([]),
        encodeUint16Vector(SUPPORTED_PROPOSALS),
        encodeUint16Vector([CREDENTIAL_TYPE_BASIC]),
    );
}

function decodeCapabilities(reader: MlsKeyPackageReader): void {
    const [versions, suites, extensions, proposals, credentials] = [
        decodeUint16Vector(reader),
        decodeUint16Vector(reader),
        decodeUint16Vector(reader),
        decodeUint16Vector(reader),
        decodeUint16Vector(reader),
    ];
    if (
        versions.length !== 1 ||
        versions[0] !== MLS_PROTOCOL_VERSION ||
        suites.length !== 1 ||
        suites[0] !== MLS_CIPHER_SUITE ||
        extensions.length !== 0 ||
        proposals.length !== SUPPORTED_PROPOSALS.length ||
        proposals.some((proposal, index) => proposal !== SUPPORTED_PROPOSALS[index]) ||
        credentials.length !== 1 ||
        credentials[0] !== CREDENTIAL_TYPE_BASIC
    ) {
        throw new Error("Unsupported MLS capabilities");
    }
}

/** Encode the fields covered by a key-package LeafNode signature. */
export function encodeLeafNodeTbs(leafNode: Omit<MlsKeyPackageLeafNode, "signature">): Uint8Array {
    return concatBytes(
        encodeOpaqueV(leafNode.encryptionKey),
        encodeOpaqueV(leafNode.signatureKey),
        encodeCredential(leafNode.credential),
        encodeCapabilities(),
        encodeOpaqueV(new Uint8Array()),
        new Uint8Array([LEAF_NODE_SOURCE_KEY_PACKAGE]),
        encodeUint64(leafNode.notBefore),
        encodeUint64(leafNode.notAfter),
    );
}

function encodeLeafNode(leafNode: MlsKeyPackageLeafNode): Uint8Array {
    return concatBytes(encodeLeafNodeTbs(leafNode), encodeOpaqueV(leafNode.signature));
}

function decodeLeafNode(reader: MlsKeyPackageReader): MlsKeyPackageLeafNode {
    const encryptionKey = reader.readOpaqueV();
    const signatureKey = reader.readOpaqueV();
    const credential = decodeCredential(reader);
    decodeCapabilities(reader);
    if (reader.readOpaqueV().length !== 0) {
        throw new Error("Unsupported LeafNode extension");
    }
    if (reader.readUint8() !== LEAF_NODE_SOURCE_KEY_PACKAGE) {
        throw new Error("Expected a key-package LeafNode");
    }
    return {
        encryptionKey,
        signatureKey,
        credential,
        notBefore: reader.readUint64(),
        notAfter: reader.readUint64(),
        signature: reader.readOpaqueV(),
    };
}

/** Encode the fields covered by the KeyPackage signature. */
export function encodeKeyPackageTbs(keyPackage: Omit<MlsKeyPackage, "signature">): Uint8Array {
    return concatBytes(
        encodeUint16(keyPackage.version),
        encodeUint16(keyPackage.cipherSuite),
        encodeOpaqueV(keyPackage.initKey),
        encodeLeafNode(keyPackage.leafNode),
        encodeOpaqueV(new Uint8Array()),
    );
}

/** Encode a complete RFC 9420 KeyPackage. */
export function encodeMlsKeyPackage(keyPackage: MlsKeyPackage): Uint8Array {
    return concatBytes(encodeKeyPackageTbs(keyPackage), encodeOpaqueV(keyPackage.signature));
}

/** Decode one KeyPackage from a containing RFC 9420 structure. */
export function decodeMlsKeyPackageFromReader(reader: MlsKeyPackageReader): MlsKeyPackage {
    const version = reader.readUint16();
    const cipherSuite = reader.readUint16();
    if (version !== MLS_PROTOCOL_VERSION || cipherSuite !== MLS_CIPHER_SUITE) {
        throw new Error("Unsupported MLS KeyPackage version or cipher suite");
    }
    const keyPackage: MlsKeyPackage = {
        version: 1,
        cipherSuite: 0x0001,
        initKey: reader.readOpaqueV(),
        leafNode: decodeLeafNode(reader),
        signature: new Uint8Array(),
    };
    if (reader.readOpaqueV().length !== 0) {
        throw new Error("Unsupported KeyPackage extension");
    }
    const signature = reader.readOpaqueV();
    return { ...keyPackage, signature };
}

/** Decode the supported RFC 9420 KeyPackage profile. */
export function decodeMlsKeyPackage(bytes: Uint8Array): MlsKeyPackage {
    const reader = new Reader(bytes);
    const keyPackage = decodeMlsKeyPackageFromReader(reader);
    reader.ensureEnd();
    return keyPackage;
}
