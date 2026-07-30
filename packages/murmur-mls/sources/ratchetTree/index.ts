import { concatBytes, encodeBase64Url, equalBytes, hashBytes } from "@slopus/murmur";
import { canonicalizeHpkePublicKey, MLS_HASH_LENGTH } from "../cipherSuite/index.js";
import { encodeOpaqueV, encodeUint32 } from "../encoding/index.js";
import { decodeMlsLeafNodeBytes, verifyMlsLeafNodeSignature } from "../leafNode/index.js";
import {
    copath,
    directPath,
    leafNode,
    leftChild,
    nodeLevel,
    parentNode,
    rightChild,
    treeRoot,
    treeWidth,
} from "../tree/index.js";
import type {
    MlsRatchetTreeLeaf,
    MlsRatchetTreeNode,
    MlsRatchetTreeParent,
    MlsRatchetTreeValidationOptions,
} from "./types.js";

export type {
    MlsRatchetTreeLeaf,
    MlsRatchetTreeNode,
    MlsRatchetTreeParent,
    MlsRatchetTreeValidationOptions,
} from "./types.js";
export { decodeMlsRatchetTree, encodeMlsRatchetTree } from "./impl/codec.js";

const MAXIMUM_LEAVES = 100_000;
const NODE_TYPE_LEAF = 1;
const NODE_TYPE_PARENT = 2;

function copyNode(node: MlsRatchetTreeNode): MlsRatchetTreeNode {
    if (node === undefined) {
        return undefined;
    }
    return node.type === "leaf"
        ? {
              type: "leaf",
              encoded: node.encoded.slice(),
              encryptionKey: node.encryptionKey.slice(),
              signatureKey: node.signatureKey.slice(),
              ...(node.parentHash === undefined ? {} : { parentHash: node.parentHash.slice() }),
          }
        : {
              type: "parent",
              encryptionKey: node.encryptionKey.slice(),
              parentHash: node.parentHash.slice(),
              unmergedLeaves: [...node.unmergedLeaves],
          };
}

function validateLeaf(leaf: MlsRatchetTreeLeaf): void {
    if (leaf.encoded.length === 0 || leaf.encoded.length > 1024 * 1024) {
        throw new Error("Invalid MLS ratchet-tree leaf");
    }
    const decoded = decodeMlsLeafNodeBytes(leaf.encoded);
    if (
        !equalBytes(decoded.encryptionKey, leaf.encryptionKey) ||
        !equalBytes(decoded.signatureKey, leaf.signatureKey) ||
        (decoded.parentHash === undefined) !== (leaf.parentHash === undefined) ||
        (decoded.parentHash !== undefined &&
            leaf.parentHash !== undefined &&
            !equalBytes(decoded.parentHash, leaf.parentHash))
    ) {
        throw new Error("MLS ratchet-tree leaf fields disagree with authenticated bytes");
    }
}

function validateParent(parent: MlsRatchetTreeParent, leafCount: number): void {
    if (
        parent.encryptionKey.length !== 32 ||
        (parent.parentHash.length !== 0 && parent.parentHash.length !== MLS_HASH_LENGTH)
    ) {
        throw new Error("Invalid MLS ratchet-tree parent");
    }
    canonicalizeHpkePublicKey(parent.encryptionKey);
    let previous = -1;
    for (const leaf of parent.unmergedLeaves) {
        if (!Number.isSafeInteger(leaf) || leaf < 0 || leaf >= leafCount || leaf <= previous) {
            throw new Error("Invalid MLS unmerged-leaf list");
        }
        previous = leaf;
    }
}

function encodeParent(parent: MlsRatchetTreeParent): Uint8Array {
    return concatBytes(
        encodeOpaqueV(parent.encryptionKey),
        encodeOpaqueV(parent.parentHash),
        encodeOpaqueV(concatBytes(...parent.unmergedLeaves.map(encodeUint32))),
    );
}

/**
 * Mutable RFC 9420 public ratchet tree.
 *
 * Nodes use the RFC array layout: leaves have even node indices and parents
 * have odd node indices. Returned values are defensive copies.
 */
export class MlsRatchetTree {
    #nodes: MlsRatchetTreeNode[];
    #leafCount: number;

    constructor(nodes: readonly MlsRatchetTreeNode[]) {
        if (nodes.length === 0 || nodes.length % 2 !== 1) {
            throw new Error("MLS ratchet tree must contain an odd number of nodes");
        }
        const leafCount = (nodes.length + 1) / 2;
        if (
            !Number.isSafeInteger(leafCount) ||
            leafCount > MAXIMUM_LEAVES ||
            (leafCount & (leafCount - 1)) !== 0
        ) {
            throw new Error("MLS ratchet tree has too many leaves");
        }
        this.#leafCount = leafCount;
        this.#nodes = nodes.map(copyNode);
        this.#validate();
    }

    /** Number of leaf positions, including blank leaves. */
    get leafCount(): number {
        return this.#leafCount;
    }

    /** Defensive snapshot of the public node array. */
    get nodes(): readonly MlsRatchetTreeNode[] {
        return this.#nodes.map(copyNode);
    }

    /** Independent candidate tree for transactional Commit processing. */
    clone(): MlsRatchetTree {
        return new MlsRatchetTree(this.#nodes);
    }

    /** Authenticate all leaves plus RFC unmerged-leaf and parent-hash invariants. */
    validate(options: MlsRatchetTreeValidationOptions): void {
        if (options.groupId.length === 0 || options.groupId.length > 255) {
            throw new Error("Invalid MLS ratchet-tree group ID");
        }
        const signatureKeys = new Set<string>();
        for (let index = 0; index < this.#nodes.length; index += 1) {
            const node = this.#nodes[index];
            if (node?.type === "leaf") {
                const leafIndex = index / 2;
                const decoded = decodeMlsLeafNodeBytes(node.encoded);
                const signatureContext =
                    decoded.source === "key_package"
                        ? undefined
                        : { groupId: options.groupId, leafIndex };
                if (
                    (index === treeRoot(this.#leafCount) &&
                        decoded.parentHash !== undefined &&
                        decoded.parentHash.length !== 0) ||
                    !verifyMlsLeafNodeSignature(decoded, signatureContext) ||
                    !options.authenticateCredential(decoded, leafIndex)
                ) {
                    throw new Error("Invalid MLS ratchet-tree LeafNode authentication");
                }
                const signatureKey = encodeBase64Url(decoded.signatureKey);
                if (signatureKeys.has(signatureKey)) {
                    throw new Error("Duplicate MLS ratchet-tree signature key");
                }
                signatureKeys.add(signatureKey);
                continue;
            }
            if (node?.type !== "parent") {
                continue;
            }
            for (const unmergedLeaf of node.unmergedLeaves) {
                const unmergedNode = this.#nodes[leafNode(unmergedLeaf, this.#leafCount)];
                const path = directPath(unmergedLeaf, this.#leafCount);
                const parentPosition = path.indexOf(index);
                if (unmergedNode?.type !== "leaf" || parentPosition < 0) {
                    throw new Error("Invalid MLS unmerged-leaf ancestry");
                }
                for (let pathIndex = 0; pathIndex < parentPosition; pathIndex += 1) {
                    const intermediate = this.#nodes[path[pathIndex]!];
                    if (
                        intermediate?.type === "parent" &&
                        !intermediate.unmergedLeaves.includes(unmergedLeaf)
                    ) {
                        throw new Error("Invalid MLS intermediate unmerged-leaf ancestry");
                    }
                }
            }
        }
        this.#validateParentHashes();
    }

    /** RFC resolution: nearest non-blank nodes, depth-first and left-first. */
    resolution(node: number, excludedLeaves: ReadonlySet<number> = new Set()): readonly number[] {
        this.#validateNode(node);
        const value = this.#nodes[node];
        if (value !== undefined) {
            if (value.type === "leaf") {
                const leaf = node / 2;
                return excludedLeaves.has(leaf) ? [] : [node];
            }
            return [
                node,
                ...value.unmergedLeaves
                    .filter((leaf) => !excludedLeaves.has(leaf))
                    .map((leaf) => leafNode(leaf, this.#leafCount)),
            ];
        }
        if (nodeLevel(node) === 0) {
            return [];
        }
        const [left, right] = this.#children(node);
        return [
            ...this.resolution(left, excludedLeaves),
            ...this.resolution(right, excludedLeaves),
        ];
    }

    /** RFC filtered direct path for one occupied leaf. */
    filteredDirectPath(leaf: number): readonly number[] {
        this.#validateLeafIndex(leaf);
        const path = directPath(leaf, this.#leafCount);
        const siblings = copath(leaf, this.#leafCount);
        return path.filter((_, index) => {
            const sibling = siblings[index];
            return sibling !== undefined && this.resolution(sibling).length > 0;
        });
    }

    /** Add a leaf at the RFC leftmost blank position, extending if required. */
    addLeaf(leaf: MlsRatchetTreeLeaf): number {
        validateLeaf(leaf);
        this.#ensureUniqueKey(leaf.encryptionKey);
        const previousNodes = this.#nodes.map(copyNode);
        const previousLeafCount = this.#leafCount;
        let index = this.#leftmostBlankLeaf();
        try {
            if (index === undefined) {
                if (this.#leafCount * 2 > MAXIMUM_LEAVES) {
                    throw new Error("MLS ratchet tree cannot be extended");
                }
                index = this.#leafCount;
                this.#leafCount *= 2;
                this.#nodes.length = treeWidth(this.#leafCount);
            }
            for (const parentIndex of directPath(index, this.#leafCount)) {
                const parent = this.#nodes[parentIndex];
                if (parent?.type === "parent" && !parent.unmergedLeaves.includes(index)) {
                    this.#nodes[parentIndex] = {
                        ...parent,
                        unmergedLeaves: [...parent.unmergedLeaves, index].sort((a, b) => a - b),
                    };
                }
            }
            this.#nodes[leafNode(index, this.#leafCount)] = copyNode(leaf);
            return index;
        } catch (error: unknown) {
            this.#nodes = previousNodes;
            this.#leafCount = previousLeafCount;
            throw error;
        }
    }

    /** Apply an RFC Remove: blank the leaf/path and truncate the empty right edge. */
    removeLeaf(leaf: number): void {
        this.#validateLeafIndex(leaf);
        const leafNodeIndex = leafNode(leaf, this.#leafCount);
        if (this.#nodes[leafNodeIndex]?.type !== "leaf") {
            throw new Error("Cannot remove a blank MLS leaf");
        }
        const occupiedLeaves = this.#nodes.filter((node) => node?.type === "leaf").length;
        if (occupiedLeaves <= 1) {
            throw new Error("MLS group cannot remove its final member");
        }
        this.#nodes[leafNodeIndex] = undefined;
        for (const parent of directPath(leaf, this.#leafCount)) {
            this.#nodes[parent] = undefined;
        }
        let rightmost = -1;
        for (let index = 0; index < this.#leafCount; index += 1) {
            if (this.#nodes[leafNode(index, this.#leafCount)]?.type === "leaf") {
                rightmost = index;
            }
        }
        let retainedLeaves = 1;
        while (retainedLeaves <= rightmost) {
            retainedLeaves *= 2;
        }
        if (retainedLeaves < this.#leafCount) {
            this.#leafCount = retainedLeaves;
            this.#nodes.length = treeWidth(retainedLeaves);
        }
    }

    /**
     * Blank the sender path, install UpdatePath parent keys, and compute the
     * parent hash that the sender's new commit-source leaf must sign.
     */
    prepareUpdatePath(sender: number, parentKeys: readonly Uint8Array[]): Uint8Array {
        this.#validateLeafIndex(sender);
        const previousNodes = this.#nodes.map(copyNode);
        try {
            for (const parent of directPath(sender, this.#leafCount)) {
                this.#nodes[parent] = undefined;
            }
            const filtered = this.filteredDirectPath(sender);
            if (filtered.length !== parentKeys.length) {
                throw new Error("MLS UpdatePath length does not match filtered direct path");
            }
            for (let index = 0; index < filtered.length; index += 1) {
                const node = filtered[index];
                const encryptionKey = parentKeys[index];
                if (node === undefined || encryptionKey === undefined) {
                    throw new Error("Invalid MLS UpdatePath node");
                }
                canonicalizeHpkePublicKey(encryptionKey);
                this.#nodes[node] = {
                    type: "parent",
                    encryptionKey: encryptionKey.slice(),
                    parentHash: new Uint8Array(),
                    unmergedLeaves: [],
                };
            }
            this.#validateUniqueKeys();
            return this.#applyParentHashes(sender);
        } catch (error: unknown) {
            this.#nodes = previousNodes;
            throw error;
        }
    }

    /** Install the authenticated commit-source leaf after parent-hash checking. */
    setCommitLeaf(sender: number, leaf: MlsRatchetTreeLeaf): void {
        this.#validateLeafIndex(sender);
        validateLeaf(leaf);
        const expected = this.#expectedLeafParentHash(sender);
        if (
            leaf.parentHash === undefined ||
            leaf.parentHash.length !== expected.length ||
            !equalBytes(leaf.parentHash, expected)
        ) {
            throw new Error("Invalid MLS UpdatePath leaf parent hash");
        }
        const previous = this.#nodes[leafNode(sender, this.#leafCount)];
        try {
            this.#nodes[leafNode(sender, this.#leafCount)] = copyNode(leaf);
            this.#validateUniqueKeys();
        } catch (error: unknown) {
            this.#nodes[leafNode(sender, this.#leafCount)] = previous;
            throw error;
        }
    }

    /** Merge a complete authenticated UpdatePath into this candidate. */
    mergeUpdatePath(
        sender: number,
        leaf: MlsRatchetTreeLeaf,
        parentKeys: readonly Uint8Array[],
    ): void {
        const previousNodes = this.#nodes.map(copyNode);
        try {
            this.prepareUpdatePath(sender, parentKeys);
            this.setCommitLeaf(sender, leaf);
        } catch (error: unknown) {
            this.#nodes = previousNodes;
            throw error;
        }
    }

    /** RFC tree hash of a node, defaulting to the root. */
    treeHash(
        node: number = treeRoot(this.#leafCount),
        excludedLeaves: ReadonlySet<number> = new Set(),
    ): Uint8Array {
        this.#validateNode(node);
        const hashes = new Map<number, Uint8Array>();
        const stack: Array<{ readonly node: number; readonly visited: boolean }> = [
            { node, visited: false },
        ];
        while (stack.length > 0) {
            const current = stack.pop();
            if (current === undefined) {
                break;
            }
            const level = nodeLevel(current.node);
            if (level === 0) {
                const leafIndex = current.node / 2;
                const leaf = excludedLeaves.has(leafIndex) ? undefined : this.#nodes[current.node];
                if (leaf !== undefined && leaf.type !== "leaf") {
                    throw new Error("MLS parent stored at a leaf position");
                }
                hashes.set(
                    current.node,
                    hashBytes(
                        concatBytes(
                            new Uint8Array([NODE_TYPE_LEAF]),
                            encodeUint32(current.node / 2),
                            leaf === undefined
                                ? new Uint8Array([0])
                                : concatBytes(new Uint8Array([1]), leaf.encoded),
                        ),
                    ),
                );
                continue;
            }
            if (!current.visited) {
                stack.push({ node: current.node, visited: true });
                const [left, right] = this.#children(current.node);
                stack.push({ node: right, visited: false }, { node: left, visited: false });
                continue;
            }
            const [left, right] = this.#children(current.node);
            const leftHash = hashes.get(left);
            const rightHash = hashes.get(right);
            if (leftHash === undefined || rightHash === undefined) {
                throw new Error("MLS tree hash traversal failed");
            }
            const parent = this.#nodes[current.node];
            if (parent !== undefined && parent.type !== "parent") {
                throw new Error("MLS leaf stored at a parent position");
            }
            hashes.set(
                current.node,
                hashBytes(
                    concatBytes(
                        new Uint8Array([NODE_TYPE_PARENT]),
                        parent === undefined
                            ? new Uint8Array([0])
                            : concatBytes(
                                  new Uint8Array([1]),
                                  encodeParent({
                                      ...parent,
                                      unmergedLeaves: parent.unmergedLeaves.filter(
                                          (leaf) => !excludedLeaves.has(leaf),
                                      ),
                                  }),
                              ),
                        encodeOpaqueV(leftHash),
                        encodeOpaqueV(rightHash),
                    ),
                ),
            );
        }
        const rootHash = hashes.get(node);
        if (rootHash === undefined) {
            throw new Error("MLS tree root hash is missing");
        }
        return rootHash;
    }

    #children(node: number): readonly [number, number] {
        const level = nodeLevel(node);
        if (level === 0) {
            throw new Error("MLS leaf has no children");
        }
        const left = Number(BigInt(node) ^ (1n << BigInt(level - 1)));
        let right = Number(BigInt(node) ^ (3n << BigInt(level - 1)));
        while (right >= treeWidth(this.#leafCount)) {
            const rightLevel = nodeLevel(right);
            right = Number(BigInt(right) ^ (1n << BigInt(rightLevel - 1)));
        }
        return [left, right];
    }

    #leftmostBlankLeaf(): number | undefined {
        for (let leaf = 0; leaf < this.#leafCount; leaf += 1) {
            if (this.#nodes[leafNode(leaf, this.#leafCount)] === undefined) {
                return leaf;
            }
        }
        return undefined;
    }

    #validate(): void {
        const root = treeRoot(this.#leafCount);
        for (let index = 0; index < this.#nodes.length; index += 1) {
            const node = this.#nodes[index];
            if (node === undefined) {
                continue;
            }
            if (nodeLevel(index) === 0) {
                if (node.type !== "leaf") {
                    throw new Error("MLS parent stored at a leaf position");
                }
                validateLeaf(node);
            } else {
                if (node.type !== "parent") {
                    throw new Error("MLS leaf stored at a parent position");
                }
                validateParent(node, this.#leafCount);
                if (index === root && node.parentHash.length !== 0) {
                    throw new Error("MLS root parent hash must be empty");
                }
            }
        }
        this.#validateUniqueKeys();
    }

    #validateUniqueKeys(): void {
        const keys = new Set<string>();
        for (const node of this.#nodes) {
            if (node === undefined) {
                continue;
            }
            const key = encodeBase64Url(canonicalizeHpkePublicKey(node.encryptionKey));
            if (keys.has(key)) {
                throw new Error("Duplicate MLS ratchet-tree encryption key");
            }
            keys.add(key);
        }
    }

    #calculateParentHash(node: number): {
        readonly hash: Uint8Array;
        readonly parent: number | undefined;
    } {
        const root = treeRoot(this.#leafCount);
        if (node === root) {
            return { hash: new Uint8Array(), parent: undefined };
        }
        let parent = parentNode(node, this.#leafCount);
        while (parent !== root && this.#nodes[parent] === undefined) {
            parent = parentNode(parent, this.#leafCount);
        }
        const parentValue = this.#nodes[parent];
        if (parent === root && parentValue === undefined) {
            return { hash: new Uint8Array(), parent };
        }
        if (parentValue?.type !== "parent") {
            throw new Error("Invalid MLS parent-hash ancestor");
        }
        const sibling = node < parent ? rightChild(parent, this.#leafCount) : leftChild(parent);
        return {
            hash: hashBytes(
                concatBytes(
                    encodeOpaqueV(parentValue.encryptionKey),
                    encodeOpaqueV(parentValue.parentHash),
                    encodeOpaqueV(this.treeHash(sibling, new Set(parentValue.unmergedLeaves))),
                ),
            ),
            parent,
        };
    }

    #validateParentHashes(): void {
        const coverage = new Map<number, number>();
        const root = treeRoot(this.#leafCount);
        for (let leaf = 0; leaf < this.#leafCount; leaf += 1) {
            let nodeIndex = leafNode(leaf, this.#leafCount);
            let node = this.#nodes[nodeIndex];
            if (node?.type !== "leaf") {
                continue;
            }
            while (nodeIndex !== root) {
                const calculated = this.#calculateParentHash(nodeIndex);
                if (calculated.parent === undefined) {
                    break;
                }
                const expected = node.parentHash;
                if (expected === undefined || !equalBytes(expected, calculated.hash)) {
                    break;
                }
                coverage.set(calculated.parent, (coverage.get(calculated.parent) ?? 0) + 1);
                nodeIndex = calculated.parent;
                node = this.#nodes[nodeIndex];
                if (node === undefined) {
                    break;
                }
            }
        }
        for (let index = 0; index < this.#nodes.length; index += 1) {
            if (this.#nodes[index]?.type === "parent" && (coverage.get(index) ?? 0) !== 1) {
                throw new Error("Invalid MLS ratchet-tree parent-hash coverage");
            }
        }
    }

    #applyParentHashes(sender: number): Uint8Array {
        const path = directPath(sender, this.#leafCount);
        const siblings = copath(sender, this.#leafCount);
        const entries = path.flatMap((node, index) => {
            const sibling = siblings[index];
            return sibling !== undefined && this.resolution(sibling).length > 0
                ? [{ node, sibling }]
                : [];
        });
        let parentHash: Uint8Array<ArrayBufferLike> = new Uint8Array();
        for (let index = entries.length - 1; index >= 0; index -= 1) {
            const entry = entries[index];
            if (entry === undefined) {
                throw new Error("Invalid MLS filtered path");
            }
            const parent = this.#nodes[entry.node];
            if (parent?.type !== "parent") {
                throw new Error("MLS UpdatePath parent is blank");
            }
            this.#nodes[entry.node] = { ...parent, parentHash: parentHash.slice() };
            parentHash = hashBytes(
                concatBytes(
                    encodeOpaqueV(parent.encryptionKey),
                    encodeOpaqueV(parentHash),
                    encodeOpaqueV(this.treeHash(entry.sibling)),
                ),
            );
        }
        return parentHash;
    }

    #expectedLeafParentHash(sender: number): Uint8Array {
        const filtered = this.filteredDirectPath(sender);
        if (filtered.length === 0) {
            return new Uint8Array();
        }
        const lowest = filtered[0];
        if (lowest === undefined) {
            throw new Error("Invalid MLS filtered direct path");
        }
        const parent = this.#nodes[lowest];
        const sibling = copath(sender, this.#leafCount)[
            directPath(sender, this.#leafCount).indexOf(lowest)
        ];
        if (parent?.type !== "parent" || sibling === undefined) {
            throw new Error("Invalid MLS UpdatePath parent");
        }
        return hashBytes(
            concatBytes(
                encodeOpaqueV(parent.encryptionKey),
                encodeOpaqueV(parent.parentHash),
                encodeOpaqueV(this.treeHash(sibling)),
            ),
        );
    }

    #ensureUniqueKey(encryptionKey: Uint8Array): void {
        const expected = encodeBase64Url(canonicalizeHpkePublicKey(encryptionKey));
        for (const node of this.#nodes) {
            if (
                node !== undefined &&
                encodeBase64Url(canonicalizeHpkePublicKey(node.encryptionKey)) === expected
            ) {
                throw new Error("Duplicate MLS ratchet-tree encryption key");
            }
        }
    }

    #validateNode(node: number): void {
        if (!Number.isSafeInteger(node) || node < 0 || node >= this.#nodes.length) {
            throw new Error("Node is outside the MLS ratchet tree");
        }
    }

    #validateLeafIndex(leaf: number): void {
        if (!Number.isSafeInteger(leaf) || leaf < 0 || leaf >= this.#leafCount) {
            throw new Error("Leaf is outside the MLS ratchet tree");
        }
    }
}
