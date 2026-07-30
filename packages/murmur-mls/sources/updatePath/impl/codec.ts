import { concatBytes } from "@murmur/core";
import { decodeVarint, encodeOpaqueV } from "../../encoding/index.js";
import {
    decodeMlsLeafNode,
    encodeMlsLeafNode,
    type MlsLeafNodeReader,
    type MlsLeafNodeSignatureContext,
} from "../../leafNode/index.js";
import type { MlsUpdatePath, MlsUpdatePathNode } from "../types.js";

const MAXIMUM_UPDATE_PATH_BYTES = 16 * 1024 * 1024;
const MAXIMUM_PATH_NODES = 64;
const MAXIMUM_CIPHERTEXTS = 100_000;

class UpdatePathReader implements MlsLeafNodeReader {
    #offset = 0;
    constructor(readonly bytes: Uint8Array) {}
    get remaining(): number {
        return this.bytes.length - this.#offset;
    }
    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS UpdatePath");
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
    readOpaqueV(maximumBytes: number = MAXIMUM_UPDATE_PATH_BYTES): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS UpdatePath vector is too large");
        }
        const length = Number(decoded.value);
        if (this.#offset + length > this.bytes.length) {
            throw new Error("Truncated MLS UpdatePath vector");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }
}

function encodeNode(node: MlsUpdatePathNode): Uint8Array {
    return concatBytes(
        encodeOpaqueV(node.encryptionKey),
        encodeOpaqueV(
            concatBytes(
                ...node.encryptedPathSecrets.map((ciphertext) =>
                    concatBytes(
                        encodeOpaqueV(ciphertext.encapsulatedKey),
                        encodeOpaqueV(ciphertext.ciphertext),
                    ),
                ),
            ),
        ),
    );
}

/** Encode an RFC 9420 UpdatePath. */
export function encodeMlsUpdatePath(
    path: MlsUpdatePath,
    signatureContext: MlsLeafNodeSignatureContext,
): Uint8Array {
    if (path.nodes.length > MAXIMUM_PATH_NODES) {
        throw new Error("MLS UpdatePath has too many nodes");
    }
    return concatBytes(
        encodeMlsLeafNode(path.leafNode, signatureContext),
        encodeOpaqueV(concatBytes(...path.nodes.map(encodeNode))),
    );
}

/** Decode an RFC 9420 UpdatePath. */
export function decodeMlsUpdatePath(bytes: Uint8Array): MlsUpdatePath {
    if (bytes.length > MAXIMUM_UPDATE_PATH_BYTES) {
        throw new Error("MLS UpdatePath is too large");
    }
    const reader = new UpdatePathReader(bytes);
    const leafNode = decodeMlsLeafNode(reader);
    const nodesReader = new UpdatePathReader(reader.readOpaqueV(MAXIMUM_UPDATE_PATH_BYTES));
    const nodes: MlsUpdatePathNode[] = [];
    while (nodesReader.remaining > 0) {
        if (nodes.length >= MAXIMUM_PATH_NODES) {
            throw new Error("MLS UpdatePath has too many nodes");
        }
        const encryptionKey = nodesReader.readOpaqueV(32);
        const ciphertextReader = new UpdatePathReader(
            nodesReader.readOpaqueV(MAXIMUM_UPDATE_PATH_BYTES),
        );
        const encryptedPathSecrets: MlsUpdatePathNode["encryptedPathSecrets"][number][] = [];
        while (ciphertextReader.remaining > 0) {
            if (encryptedPathSecrets.length >= MAXIMUM_CIPHERTEXTS) {
                throw new Error("MLS UpdatePath has too many ciphertexts");
            }
            encryptedPathSecrets.push({
                encapsulatedKey: ciphertextReader.readOpaqueV(32),
                ciphertext: ciphertextReader.readOpaqueV(MAXIMUM_UPDATE_PATH_BYTES),
            });
        }
        nodes.push({ encryptionKey, encryptedPathSecrets });
    }
    if (reader.remaining !== 0) {
        throw new Error("Trailing bytes in MLS UpdatePath");
    }
    return { leafNode, nodes };
}
