import { concatBytes, equalBytes } from "../internal.js";
import {
    canonicalizeHpkePublicKey,
    MLS_CIPHER_SUITE,
    MLS_PROTOCOL_VERSION,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import {
    decodeVarint,
    encodeOpaqueV,
    encodeUint16,
    encodeUint32,
    encodeUint64,
} from "../encoding/index.js";
import type {
    MlsLeafCapabilities,
    MlsLeafExtension,
    MlsLeafNode,
    MlsLeafNodeSignatureContext,
} from "./types.js";

export type {
    MlsLeafCapabilities,
    MlsLeafExtension,
    MlsLeafNode,
    MlsLeafNodeSignatureContext,
} from "./types.js";

export interface MlsLeafNodeReader {
    readUint8(): number;
    readUint16(): number;
    readUint32(): number;
    readUint64(): bigint;
    readOpaqueV(maximumBytes?: number): Uint8Array;
}

const CREDENTIAL_TYPE_BASIC = 1;
const SOURCE_KEY_PACKAGE = 1;
const SOURCE_UPDATE = 2;
const SOURCE_COMMIT = 3;
const MAXIMUM_VECTOR_BYTES = 1024 * 1024;
const DEFAULT_PROPOSALS = new Set([1, 2, 3, 4, 5, 6, 7]);
const DEFAULT_EXTENSIONS = new Set([1, 2, 3, 4, 5]);

class LeafNodeBytesReader implements MlsLeafNodeReader {
    #offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    get remaining(): number {
        return this.bytes.length - this.#offset;
    }

    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS LeafNode");
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

    readOpaqueV(maximumBytes: number = MAXIMUM_VECTOR_BYTES): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS LeafNode vector is too large");
        }
        const length = Number(decoded.value);
        if (this.#offset + length > this.bytes.length) {
            throw new Error("Truncated MLS LeafNode vector");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }
}

/** Murmur's extension-free capabilities for RFC cipher suite 0x0001. */
export function defaultMlsLeafCapabilities(): MlsLeafCapabilities {
    return {
        versions: [MLS_PROTOCOL_VERSION],
        cipherSuites: [MLS_CIPHER_SUITE],
        extensions: [],
        proposals: [],
        credentials: [CREDENTIAL_TYPE_BASIC],
    };
}

function encodeUint16Vector(values: readonly number[]): Uint8Array {
    return encodeOpaqueV(concatBytes(...values.map(encodeUint16)));
}

function decodeUint16Vector(reader: MlsLeafNodeReader): readonly number[] {
    const bytes = reader.readOpaqueV(MAXIMUM_VECTOR_BYTES);
    if (bytes.length % 2 !== 0) {
        throw new Error("Invalid MLS uint16 vector");
    }
    const values: number[] = [];
    for (let index = 0; index < bytes.length; index += 2) {
        values.push(((bytes[index] ?? 0) << 8) | (bytes[index + 1] ?? 0));
    }
    return values;
}

function encodeCapabilities(capabilities: MlsLeafCapabilities): Uint8Array {
    validateCapabilities(capabilities);
    return concatBytes(
        encodeUint16Vector(capabilities.versions),
        encodeUint16Vector(capabilities.cipherSuites),
        encodeUint16Vector(capabilities.extensions),
        encodeUint16Vector(capabilities.proposals),
        encodeUint16Vector(capabilities.credentials),
    );
}

function decodeCapabilities(reader: MlsLeafNodeReader): MlsLeafCapabilities {
    const capabilities: MlsLeafCapabilities = {
        versions: decodeUint16Vector(reader),
        cipherSuites: decodeUint16Vector(reader),
        extensions: decodeUint16Vector(reader),
        proposals: decodeUint16Vector(reader),
        credentials: decodeUint16Vector(reader),
    };
    validateCapabilities(capabilities);
    return capabilities;
}

function validateCapabilities(capabilities: MlsLeafCapabilities): void {
    for (const values of [
        capabilities.versions,
        capabilities.cipherSuites,
        capabilities.extensions,
        capabilities.proposals,
        capabilities.credentials,
    ]) {
        if (
            values.length > 1024 ||
            values.some((value) => !Number.isSafeInteger(value) || value < 0 || value > 0xffff) ||
            new Set(values).size !== values.length
        ) {
            throw new Error("Invalid MLS LeafNode capabilities");
        }
    }
    if (
        !capabilities.versions.includes(MLS_PROTOCOL_VERSION) ||
        !capabilities.cipherSuites.includes(MLS_CIPHER_SUITE) ||
        !capabilities.credentials.includes(CREDENTIAL_TYPE_BASIC) ||
        capabilities.proposals.some((type) => DEFAULT_PROPOSALS.has(type)) ||
        capabilities.extensions.some((type) => DEFAULT_EXTENSIONS.has(type))
    ) {
        throw new Error("Unsupported MLS LeafNode capabilities");
    }
}

function encodeCredential(identity: Uint8Array): Uint8Array {
    if (identity.length === 0 || identity.length > 1024) {
        throw new Error("Invalid MLS BasicCredential");
    }
    return concatBytes(encodeUint16(CREDENTIAL_TYPE_BASIC), encodeOpaqueV(identity));
}

function decodeCredential(reader: MlsLeafNodeReader): Uint8Array {
    if (reader.readUint16() !== CREDENTIAL_TYPE_BASIC) {
        throw new Error("Unsupported MLS credential type");
    }
    const identity = reader.readOpaqueV(1024);
    if (identity.length === 0) {
        throw new Error("Invalid MLS BasicCredential");
    }
    return identity;
}

function encodeExtensions(extensions: readonly MlsLeafExtension[]): Uint8Array {
    if (extensions.length > 1024) {
        throw new Error("Too many MLS LeafNode extensions");
    }
    const types = new Set<number>();
    return encodeOpaqueV(
        concatBytes(
            ...extensions.map((extension) => {
                if (
                    !Number.isSafeInteger(extension.type) ||
                    extension.type < 0 ||
                    extension.type > 0xffff ||
                    extension.data.length > MAXIMUM_VECTOR_BYTES ||
                    types.has(extension.type)
                ) {
                    throw new Error("Invalid MLS LeafNode extension");
                }
                types.add(extension.type);
                return concatBytes(encodeUint16(extension.type), encodeOpaqueV(extension.data));
            }),
        ),
    );
}

function decodeExtensions(reader: MlsLeafNodeReader): readonly MlsLeafExtension[] {
    const vector = reader.readOpaqueV(MAXIMUM_VECTOR_BYTES);
    let offset = 0;
    const extensions: MlsLeafExtension[] = [];
    const types = new Set<number>();
    while (offset < vector.length) {
        if (offset + 2 > vector.length || extensions.length >= 1024) {
            throw new Error("Truncated MLS LeafNode extension");
        }
        const type = ((vector[offset] ?? 0) << 8) | (vector[offset + 1] ?? 0);
        offset += 2;
        const decoded = decodeVarint(vector, offset);
        offset += decoded.bytesRead;
        if (
            decoded.value > BigInt(MAXIMUM_VECTOR_BYTES) ||
            offset + Number(decoded.value) > vector.length
        ) {
            throw new Error("Truncated MLS LeafNode extension data");
        }
        if (types.has(type)) {
            throw new Error("Duplicate MLS LeafNode extension");
        }
        types.add(type);
        extensions.push({
            type,
            data: vector.slice(offset, offset + Number(decoded.value)),
        });
        offset += Number(decoded.value);
    }
    return extensions;
}

function sourceByte(source: MlsLeafNode["source"]): number {
    switch (source) {
        case "key_package":
            return SOURCE_KEY_PACKAGE;
        case "update":
            return SOURCE_UPDATE;
        case "commit":
            return SOURCE_COMMIT;
    }
}

function validateLeafNode(
    leafNode: MlsLeafNode,
    signatureContext?: MlsLeafNodeSignatureContext,
): void {
    canonicalizeHpkePublicKey(leafNode.encryptionKey);
    if (
        leafNode.signatureKey.length !== 32 ||
        leafNode.credential.identity.length === 0 ||
        leafNode.credential.identity.length > 1024 ||
        leafNode.signature.length !== 64 ||
        leafNode.extensions.some(
            (extension) =>
                !DEFAULT_EXTENSIONS.has(extension.type) &&
                !leafNode.capabilities.extensions.includes(extension.type),
        )
    ) {
        throw new Error("Invalid MLS LeafNode");
    }
    if (
        leafNode.source === "key_package"
            ? leafNode.notBefore === undefined ||
              leafNode.notAfter === undefined ||
              leafNode.notBefore < 0n ||
              leafNode.notAfter < leafNode.notBefore ||
              signatureContext !== undefined
            : signatureContext === undefined
    ) {
        throw new Error("Invalid MLS LeafNode source context");
    }
    if (
        signatureContext !== undefined &&
        (signatureContext.groupId.length === 0 ||
            signatureContext.groupId.length > 255 ||
            !Number.isSafeInteger(signatureContext.leafIndex) ||
            signatureContext.leafIndex < 0 ||
            signatureContext.leafIndex > 0xffff_ffff)
    ) {
        throw new Error("Invalid MLS LeafNode signature context");
    }
    if (
        leafNode.source === "commit" &&
        (leafNode.parentHash === undefined ||
            (leafNode.parentHash.length !== 0 && leafNode.parentHash.length !== 32))
    ) {
        throw new Error("Invalid MLS commit LeafNode parent hash");
    }
    validateCapabilities(leafNode.capabilities);
}

function encodeMlsLeafNodePayload(leafNode: Omit<MlsLeafNode, "signature">): Uint8Array {
    const sourceData =
        leafNode.source === "key_package"
            ? concatBytes(encodeUint64(leafNode.notBefore!), encodeUint64(leafNode.notAfter!))
            : leafNode.source === "commit"
              ? encodeOpaqueV(leafNode.parentHash!)
              : new Uint8Array();
    return concatBytes(
        encodeOpaqueV(leafNode.encryptionKey),
        encodeOpaqueV(leafNode.signatureKey),
        encodeCredential(leafNode.credential.identity),
        encodeCapabilities(leafNode.capabilities),
        new Uint8Array([sourceByte(leafNode.source)]),
        sourceData,
        encodeExtensions(leafNode.extensions),
    );
}

/** Encode the RFC fields covered by a LeafNode signature. */
export function encodeMlsLeafNodeTbs(
    leafNode: Omit<MlsLeafNode, "signature">,
    signatureContext?: MlsLeafNodeSignatureContext,
): Uint8Array {
    const complete = { ...leafNode, signature: new Uint8Array(64) };
    validateLeafNode(complete, signatureContext);
    return concatBytes(
        encodeMlsLeafNodePayload(leafNode),
        leafNode.source === "key_package"
            ? new Uint8Array()
            : concatBytes(
                  encodeOpaqueV(signatureContext!.groupId),
                  encodeUint32(signatureContext!.leafIndex),
              ),
    );
}

/** Encode a complete RFC 9420 LeafNode. */
export function encodeMlsLeafNode(
    leafNode: MlsLeafNode,
    signatureContext?: MlsLeafNodeSignatureContext,
): Uint8Array {
    validateLeafNode(leafNode, signatureContext);
    return concatBytes(encodeMlsLeafNodePayload(leafNode), encodeOpaqueV(leafNode.signature));
}

/** Decode one RFC 9420 LeafNode from a containing structure. */
export function decodeMlsLeafNode(reader: MlsLeafNodeReader): MlsLeafNode {
    const encryptionKey = reader.readOpaqueV(32);
    const signatureKey = reader.readOpaqueV(32);
    const identity = decodeCredential(reader);
    const capabilities = decodeCapabilities(reader);
    const sourceValue = reader.readUint8();
    const source: MlsLeafNode["source"] =
        sourceValue === SOURCE_KEY_PACKAGE
            ? "key_package"
            : sourceValue === SOURCE_UPDATE
              ? "update"
              : sourceValue === SOURCE_COMMIT
                ? "commit"
                : (() => {
                      throw new Error("Unsupported MLS LeafNode source");
                  })();
    const sourceFields =
        source === "key_package"
            ? { notBefore: reader.readUint64(), notAfter: reader.readUint64() }
            : source === "commit"
              ? { parentHash: reader.readOpaqueV(32) }
              : {};
    return {
        encryptionKey,
        signatureKey,
        credential: { identity },
        capabilities,
        source,
        ...sourceFields,
        extensions: decodeExtensions(reader),
        signature: reader.readOpaqueV(64),
    };
}

/** Decode one standalone, canonical RFC 9420 LeafNode. */
export function decodeMlsLeafNodeBytes(bytes: Uint8Array): MlsLeafNode {
    if (bytes.length === 0 || bytes.length > MAXIMUM_VECTOR_BYTES) {
        throw new Error("Invalid MLS LeafNode encoding");
    }
    const reader = new LeafNodeBytesReader(bytes);
    const leafNode = decodeMlsLeafNode(reader);
    if (reader.remaining !== 0) {
        throw new Error("Trailing bytes in MLS LeafNode");
    }
    const signatureContext =
        leafNode.source === "key_package"
            ? undefined
            : { groupId: new Uint8Array([1]), leafIndex: 0 };
    if (!equalBytes(encodeMlsLeafNode(leafNode, signatureContext), bytes)) {
        throw new Error("Noncanonical MLS LeafNode encoding");
    }
    return leafNode;
}

/** Verify a LeafNode signature in its RFC source-specific context. */
export function verifyMlsLeafNodeSignature(
    leafNode: MlsLeafNode,
    signatureContext?: MlsLeafNodeSignatureContext,
): boolean {
    try {
        return mlsVerifyWithLabel(
            leafNode.signatureKey,
            "LeafNodeTBS",
            encodeMlsLeafNodeTbs(leafNode, signatureContext),
            leafNode.signature,
        );
    } catch {
        return false;
    }
}
