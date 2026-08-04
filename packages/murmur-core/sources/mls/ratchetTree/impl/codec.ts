import { concatBytes } from "../../internal.js";
import { decodeVarint, encodeOpaqueV, encodeUint32 } from "../../encoding/index.js";
import { decodeMlsLeafNode, type MlsLeafNodeReader } from "../../leafNode/index.js";
import {
    MlsRatchetTree,
    type MlsRatchetTreeNode,
    type MlsRatchetTreeValidationOptions,
} from "../index.js";

const NODE_TYPE_LEAF = 1;
const NODE_TYPE_PARENT = 2;
const MAXIMUM_TREE_BYTES = 16 * 1024 * 1024;
const MAXIMUM_NODES = 200_000;
const MAXIMUM_UNMERGED_LEAVES = 100_000;

class RatchetTreeReader implements MlsLeafNodeReader {
    #offset = 0;
    constructor(readonly bytes: Uint8Array) {}
    get offset(): number {
        return this.#offset;
    }
    get remaining(): number {
        return this.bytes.length - this.#offset;
    }
    readUint8(): number {
        if (this.#offset >= this.bytes.length) {
            throw new Error("Truncated MLS ratchet tree");
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
    readOpaqueV(maximumBytes: number = MAXIMUM_TREE_BYTES): Uint8Array {
        const decoded = decodeVarint(this.bytes, this.#offset);
        this.#offset += decoded.bytesRead;
        if (decoded.value > BigInt(maximumBytes)) {
            throw new Error("MLS ratchet-tree vector is too large");
        }
        const length = Number(decoded.value);
        if (this.#offset + length > this.bytes.length) {
            throw new Error("Truncated MLS ratchet-tree vector");
        }
        const result = this.bytes.slice(this.#offset, this.#offset + length);
        this.#offset += length;
        return result;
    }
}

function decodeParent(reader: RatchetTreeReader): MlsRatchetTreeNode {
    const encryptionKey = reader.readOpaqueV(32);
    const parentHash = reader.readOpaqueV(32);
    const leaves = new RatchetTreeReader(reader.readOpaqueV(MAXIMUM_UNMERGED_LEAVES * 4));
    if (leaves.remaining % 4 !== 0) {
        throw new Error("Invalid MLS unmerged-leaf vector");
    }
    const unmergedLeaves: number[] = [];
    while (leaves.remaining > 0) {
        unmergedLeaves.push(leaves.readUint32());
    }
    return { type: "parent", encryptionKey, parentHash, unmergedLeaves };
}

function encodeNode(node: MlsRatchetTreeNode): Uint8Array {
    if (node === undefined) {
        return new Uint8Array([0]);
    }
    if (node.type === "leaf") {
        return concatBytes(new Uint8Array([1, NODE_TYPE_LEAF]), node.encoded);
    }
    return concatBytes(
        new Uint8Array([1, NODE_TYPE_PARENT]),
        encodeOpaqueV(node.encryptionKey),
        encodeOpaqueV(node.parentHash),
        encodeOpaqueV(concatBytes(...node.unmergedLeaves.map(encodeUint32))),
    );
}

/** Encode the RFC ratchet_tree extension value. */
export function encodeMlsRatchetTree(tree: MlsRatchetTree): Uint8Array {
    const nodes = tree.nodes;
    let finalNode = nodes.length - 1;
    while (finalNode >= 0 && nodes[finalNode] === undefined) {
        finalNode -= 1;
    }
    if (finalNode < 0) {
        throw new Error("MLS ratchet tree cannot be entirely blank");
    }
    return encodeOpaqueV(
        concatBytes(
            ...Array.from({ length: finalNode + 1 }, (_, index) => encodeNode(nodes[index])),
        ),
    );
}

/** Decode an RFC ratchet_tree extension value. */
export function decodeMlsRatchetTree(
    bytes: Uint8Array,
    validation: MlsRatchetTreeValidationOptions,
): MlsRatchetTree {
    if (bytes.length > MAXIMUM_TREE_BYTES) {
        throw new Error("MLS ratchet tree is too large");
    }
    const outer = new RatchetTreeReader(bytes);
    const reader = new RatchetTreeReader(outer.readOpaqueV(MAXIMUM_TREE_BYTES));
    if (outer.remaining !== 0) {
        throw new Error("Trailing bytes after MLS ratchet tree");
    }
    const nodes: MlsRatchetTreeNode[] = [];
    while (reader.remaining > 0) {
        if (nodes.length >= MAXIMUM_NODES) {
            throw new Error("MLS ratchet tree has too many nodes");
        }
        const present = reader.readUint8();
        if (present === 0) {
            nodes.push(undefined);
            continue;
        }
        if (present !== 1) {
            throw new Error("Invalid MLS ratchet-tree optional node");
        }
        const nodeType = reader.readUint8();
        if (nodeType === NODE_TYPE_PARENT) {
            nodes.push(decodeParent(reader));
            continue;
        }
        if (nodeType !== NODE_TYPE_LEAF) {
            throw new Error("Unsupported MLS ratchet-tree node type");
        }
        const start = reader.offset;
        const leaf = decodeMlsLeafNode(reader);
        nodes.push({
            type: "leaf",
            encoded: reader.bytes.slice(start, reader.offset),
            encryptionKey: leaf.encryptionKey,
            signatureKey: leaf.signatureKey,
            ...(leaf.parentHash === undefined ? {} : { parentHash: leaf.parentHash }),
        });
    }
    if (nodes.length === 0 || nodes[nodes.length - 1] === undefined) {
        throw new Error("MLS ratchet tree must end in a non-blank node");
    }
    let paddedLength = 1;
    while (paddedLength < nodes.length) {
        paddedLength = paddedLength * 2 + 1;
    }
    if (paddedLength > MAXIMUM_NODES) {
        throw new Error("MLS ratchet tree has too many nodes");
    }
    while (nodes.length < paddedLength) {
        nodes.push(undefined);
    }
    const leafCount = (paddedLength + 1) / 2;
    let unmergedEntries = 0;
    for (const node of nodes) {
        if (node?.type !== "parent") {
            continue;
        }
        if (node.unmergedLeaves.length > leafCount) {
            throw new Error("MLS parent has too many unmerged leaves");
        }
        unmergedEntries += node.unmergedLeaves.length;
    }
    if (unmergedEntries > leafCount * Math.log2(leafCount)) {
        throw new Error("MLS ratchet tree has too many unmerged-leaf entries");
    }
    const tree = new MlsRatchetTree(nodes);
    tree.validate(validation);
    return tree;
}
