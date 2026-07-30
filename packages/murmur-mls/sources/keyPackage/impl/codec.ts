import { concatBytes } from "@murmur/core";
import { MLS_CIPHER_SUITE, MLS_PROTOCOL_VERSION } from "../../cipherSuite/index.js";
import { decodeVarint, encodeOpaqueV, encodeUint16 } from "../../encoding/index.js";
import {
    decodeMlsLeafNode,
    defaultMlsLeafCapabilities,
    encodeMlsLeafNode,
    encodeMlsLeafNodeTbs,
    type MlsLeafNode,
    type MlsLeafNodeReader,
} from "../../leafNode/index.js";
import type { MlsKeyPackage, MlsKeyPackageLeafNode } from "../types.js";

export interface MlsKeyPackageReader extends MlsLeafNodeReader {}

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

    readOpaqueV(maximumBytes: number = 16 * 1024 * 1024): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
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

function genericLeafNodeTbs(
    leafNode: Omit<MlsKeyPackageLeafNode, "signature">,
): Omit<MlsLeafNode, "signature"> {
    return {
        encryptionKey: leafNode.encryptionKey,
        signatureKey: leafNode.signatureKey,
        credential: leafNode.credential,
        capabilities: defaultMlsLeafCapabilities(),
        source: "key_package",
        notBefore: leafNode.notBefore,
        notAfter: leafNode.notAfter,
        extensions: [],
    };
}

/** Encode the fields covered by a key-package LeafNode signature. */
export function encodeLeafNodeTbs(leafNode: Omit<MlsKeyPackageLeafNode, "signature">): Uint8Array {
    return encodeMlsLeafNodeTbs(genericLeafNodeTbs(leafNode));
}

/** Encode a complete KeyPackage-source LeafNode. */
export function encodeKeyPackageLeafNode(leafNode: MlsKeyPackageLeafNode): Uint8Array {
    return encodeMlsLeafNode({
        ...genericLeafNodeTbs(leafNode),
        signature: leafNode.signature,
    });
}

function decodeKeyPackageLeafNode(reader: MlsKeyPackageReader): MlsKeyPackageLeafNode {
    const leafNode = decodeMlsLeafNode(reader);
    if (
        leafNode.source !== "key_package" ||
        leafNode.notBefore === undefined ||
        leafNode.notAfter === undefined ||
        leafNode.extensions.length !== 0
    ) {
        throw new Error("Expected an extension-free key-package LeafNode");
    }
    return {
        encryptionKey: leafNode.encryptionKey,
        signatureKey: leafNode.signatureKey,
        credential: leafNode.credential,
        notBefore: leafNode.notBefore,
        notAfter: leafNode.notAfter,
        signature: leafNode.signature,
    };
}

/** Encode the fields covered by the KeyPackage signature. */
export function encodeKeyPackageTbs(keyPackage: Omit<MlsKeyPackage, "signature">): Uint8Array {
    return concatBytes(
        encodeUint16(keyPackage.version),
        encodeUint16(keyPackage.cipherSuite),
        encodeOpaqueV(keyPackage.initKey),
        encodeKeyPackageLeafNode(keyPackage.leafNode),
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
        initKey: reader.readOpaqueV(32),
        leafNode: decodeKeyPackageLeafNode(reader),
        signature: new Uint8Array(),
    };
    if (reader.readOpaqueV(0).length !== 0) {
        throw new Error("Unsupported KeyPackage extension");
    }
    return { ...keyPackage, signature: reader.readOpaqueV(64) };
}

/** Decode the supported RFC 9420 KeyPackage profile. */
export function decodeMlsKeyPackage(bytes: Uint8Array): MlsKeyPackage {
    const reader = new Reader(bytes);
    const keyPackage = decodeMlsKeyPackageFromReader(reader);
    reader.ensureEnd();
    return keyPackage;
}
