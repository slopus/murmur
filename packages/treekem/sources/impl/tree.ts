import { byteIdentifier, concatBytes, encodeUint32, equalBytes, utf8Encode } from "./bytes.js";
import { canonicalizePublicKey, hash } from "./crypto.js";

export const MAXIMUM_LEAVES = 4096;

export interface PublicLeaf {
    readonly type: "leaf";
    readonly encryptionKey: Uint8Array;
    readonly signatureKey: Uint8Array;
}

export interface PublicParent {
    readonly type: "parent";
    readonly encryptionKey: Uint8Array;
    readonly unmergedLeaves: readonly number[];
}

export type PublicNode = PublicLeaf | PublicParent | undefined;

export interface PublicTree {
    readonly leafCount: number;
    readonly nodes: readonly PublicNode[];
}

export interface PathEntry {
    readonly node: number;
    readonly sibling: number;
}

const TREE_HASH_DOMAIN = utf8Encode("public tree");

function validateLeafCount(leafCount: number): void {
    if (
        !Number.isSafeInteger(leafCount) ||
        leafCount < 1 ||
        leafCount > MAXIMUM_LEAVES ||
        (leafCount & (leafCount - 1)) !== 0
    ) {
        throw new Error("TreeKEM leaf capacity must be a supported power of two");
    }
}

/** Number of nodes in the left-balanced array representation. */
export function treeWidth(leafCount: number): number {
    validateLeafCount(leafCount);
    return 2 * leafCount - 1;
}

/** Convert a zero-based leaf position to its even node index. */
export function leafNode(leaf: number, leafCount: number): number {
    validateLeafCount(leafCount);
    if (!Number.isSafeInteger(leaf) || leaf < 0 || leaf >= leafCount) {
        throw new Error("Leaf is outside the TreeKEM tree");
    }
    return 2 * leaf;
}

/** Count consecutive low one bits in an RFC left-balanced node index. */
export function nodeLevel(node: number): number {
    if (!Number.isSafeInteger(node) || node < 0) {
        throw new Error("TreeKEM node must be a non-negative safe integer");
    }
    let value = BigInt(node);
    let level = 0;
    while ((value & 1n) === 1n) {
        level += 1;
        value >>= 1n;
    }
    return level;
}

/** Root node index for a power-of-two leaf capacity. */
export function treeRoot(leafCount: number): number {
    validateLeafCount(leafCount);
    return leafCount - 1;
}

/** Left child of a parent node. */
export function leftChild(node: number): number {
    const level = nodeLevel(node);
    if (level === 0) {
        throw new Error("A TreeKEM leaf has no child");
    }
    return Number(BigInt(node) ^ (1n << BigInt(level - 1)));
}

/** Right child of a parent node in a perfect-capacity tree. */
export function rightChild(node: number): number {
    const level = nodeLevel(node);
    if (level === 0) {
        throw new Error("A TreeKEM leaf has no child");
    }
    return Number(BigInt(node) ^ (3n << BigInt(level - 1)));
}

/** Parent node in a perfect-capacity tree. */
export function parentNode(node: number, leafCount: number): number {
    validateLeafCount(leafCount);
    if (!Number.isSafeInteger(node) || node < 0 || node >= treeWidth(leafCount)) {
        throw new Error("Node is outside the TreeKEM tree");
    }
    if (node === treeRoot(leafCount)) {
        throw new Error("The TreeKEM root has no parent");
    }
    const level = nodeLevel(node);
    const value = BigInt(node);
    return Number((value | (1n << BigInt(level))) & ~(1n << BigInt(level + 1)));
}

/** Sibling node in a perfect-capacity tree. */
export function siblingNode(node: number, leafCount: number): number {
    const parent = parentNode(node, leafCount);
    return node < parent ? rightChild(parent) : leftChild(parent);
}

/** Parent nodes from a leaf through the root. */
export function directPath(leaf: number, leafCount: number): readonly number[] {
    let node = leafNode(leaf, leafCount);
    const root = treeRoot(leafCount);
    const result: number[] = [];
    while (node !== root) {
        node = parentNode(node, leafCount);
        result.push(node);
    }
    return result;
}

/** Sibling subtree corresponding to every direct-path node. */
export function copath(leaf: number, leafCount: number): readonly number[] {
    let node = leafNode(leaf, leafCount);
    const root = treeRoot(leafCount);
    const result: number[] = [];
    while (node !== root) {
        result.push(siblingNode(node, leafCount));
        node = parentNode(node, leafCount);
    }
    return result;
}

function copyNode(node: PublicNode): PublicNode {
    if (node === undefined) {
        return undefined;
    }
    return node.type === "leaf"
        ? {
              type: "leaf",
              encryptionKey: node.encryptionKey.slice(),
              signatureKey: node.signatureKey.slice(),
          }
        : {
              type: "parent",
              encryptionKey: node.encryptionKey.slice(),
              unmergedLeaves: [...node.unmergedLeaves],
          };
}

/** Deep-copy a public tree before a functional transformation. */
export function cloneTree(tree: PublicTree): PublicTree {
    return {
        leafCount: tree.leafCount,
        nodes: Array.from({ length: tree.nodes.length }, (_, index) => copyNode(tree.nodes[index])),
    };
}

/** Create the initial one-leaf public tree. */
export function createPublicTree(leaf: PublicLeaf): PublicTree {
    const tree: PublicTree = { leafCount: 1, nodes: [copyNode(leaf)] };
    validateTree(tree);
    return tree;
}

/** Return an occupied leaf or fail for a blank/out-of-range position. */
export function getLeaf(tree: PublicTree, leaf: number): PublicLeaf {
    const node = tree.nodes[leafNode(leaf, tree.leafCount)];
    if (node?.type !== "leaf") {
        throw new Error("TreeKEM leaf is blank");
    }
    return node;
}

/** Find a stable member signing key in the public leaves. */
export function findLeafBySignatureKey(
    tree: PublicTree,
    signatureKey: Uint8Array,
): number | undefined {
    for (let leaf = 0; leaf < tree.leafCount; leaf += 1) {
        const node = tree.nodes[leafNode(leaf, tree.leafCount)];
        if (node?.type === "leaf" && equalBytes(node.signatureKey, signatureKey)) {
            return leaf;
        }
    }
    return undefined;
}

/** RFC resolution with unmerged leaves and optional exclusions. */
export function resolution(
    tree: PublicTree,
    node: number,
    excludedLeaves: ReadonlySet<number> = new Set(),
): readonly number[] {
    if (!Number.isSafeInteger(node) || node < 0 || node >= tree.nodes.length) {
        throw new Error("Node is outside the TreeKEM tree");
    }
    const value = tree.nodes[node];
    if (value?.type === "leaf") {
        const leaf = node / 2;
        return excludedLeaves.has(leaf) ? [] : [node];
    }
    if (value?.type === "parent") {
        return [
            node,
            ...value.unmergedLeaves
                .filter((leaf) => !excludedLeaves.has(leaf))
                .map((leaf) => leafNode(leaf, tree.leafCount)),
        ];
    }
    if (nodeLevel(node) === 0) {
        return [];
    }
    return [
        ...resolution(tree, leftChild(node), excludedLeaves),
        ...resolution(tree, rightChild(node), excludedLeaves),
    ];
}

/** Filter a sender direct path to levels whose copath is non-empty. */
export function pathEntries(tree: PublicTree, sender: number): readonly PathEntry[] {
    getLeaf(tree, sender);
    const parents = directPath(sender, tree.leafCount);
    const siblings = copath(sender, tree.leafCount);
    return parents.flatMap((node, index) => {
        const sibling = siblings[index];
        return sibling !== undefined && resolution(tree, sibling).length > 0
            ? [{ node, sibling }]
            : [];
    });
}

/** Blank a member's direct path before installing fresh parent keys. */
export function blankDirectPath(tree: PublicTree, sender: number): PublicTree {
    getLeaf(tree, sender);
    const nodes = tree.nodes.map(copyNode);
    for (const node of directPath(sender, tree.leafCount)) {
        nodes[node] = undefined;
    }
    return { leafCount: tree.leafCount, nodes };
}

/** Replace the sender leaf with its fresh encryption key. */
export function setLeaf(tree: PublicTree, leaf: number, value: PublicLeaf): PublicTree {
    getLeaf(tree, leaf);
    canonicalizePublicKey(value.encryptionKey);
    if (value.signatureKey.length !== 32) {
        throw new Error("TreeKEM signature public key must be 32 bytes");
    }
    const nodes = tree.nodes.map(copyNode);
    nodes[leafNode(leaf, tree.leafCount)] = copyNode(value);
    return { leafCount: tree.leafCount, nodes };
}

/** Install one fresh parent key and clear its unmerged list. */
export function setParent(tree: PublicTree, node: number, encryptionKey: Uint8Array): PublicTree {
    if (nodeLevel(node) === 0 || node < 0 || node >= tree.nodes.length) {
        throw new Error("Invalid TreeKEM parent node");
    }
    const key = canonicalizePublicKey(encryptionKey);
    const nodes = tree.nodes.map(copyNode);
    nodes[node] = { type: "parent", encryptionKey: key, unmergedLeaves: [] };
    return { leafCount: tree.leafCount, nodes };
}

function firstBlankLeaf(tree: PublicTree): number | undefined {
    for (let leaf = 0; leaf < tree.leafCount; leaf += 1) {
        if (tree.nodes[leafNode(leaf, tree.leafCount)] === undefined) {
            return leaf;
        }
    }
    return undefined;
}

/** Add a leaf at the leftmost blank position, extending capacity when full. */
export function addLeaf(
    input: PublicTree,
    value: PublicLeaf,
): { readonly tree: PublicTree; readonly leaf: number } {
    canonicalizePublicKey(value.encryptionKey);
    if (value.signatureKey.length !== 32) {
        throw new Error("TreeKEM signature public key must be 32 bytes");
    }
    let tree = cloneTree(input);
    let leaf = firstBlankLeaf(tree);
    if (leaf === undefined) {
        if (tree.leafCount * 2 > MAXIMUM_LEAVES) {
            throw new Error("TreeKEM group is full");
        }
        const leafCount = tree.leafCount * 2;
        tree = {
            leafCount,
            nodes: [
                ...tree.nodes.map(copyNode),
                ...Array.from<PublicNode>({ length: treeWidth(leafCount) - tree.nodes.length }),
            ],
        };
        leaf = input.leafCount;
    }
    const nodes = tree.nodes.map(copyNode);
    for (const parent of directPath(leaf, tree.leafCount)) {
        const node = nodes[parent];
        if (node?.type === "parent" && !node.unmergedLeaves.includes(leaf)) {
            nodes[parent] = {
                ...node,
                unmergedLeaves: [...node.unmergedLeaves, leaf].sort((left, right) => left - right),
            };
        }
    }
    nodes[leafNode(leaf, tree.leafCount)] = copyNode(value);
    return { tree: { leafCount: tree.leafCount, nodes }, leaf };
}

/** Remove a leaf, its path, and every unmerged-leaf reference to it. */
export function removeLeaf(tree: PublicTree, leaf: number): PublicTree {
    getLeaf(tree, leaf);
    let occupied = 0;
    for (let index = 0; index < tree.leafCount; index += 1) {
        if (tree.nodes[leafNode(index, tree.leafCount)]?.type === "leaf") {
            occupied += 1;
        }
    }
    if (occupied <= 1) {
        throw new Error("TreeKEM cannot remove its final member");
    }
    const nodes = tree.nodes.map((node) => {
        if (node?.type !== "parent" || !node.unmergedLeaves.includes(leaf)) {
            return copyNode(node);
        }
        return {
            ...node,
            unmergedLeaves: node.unmergedLeaves.filter((value) => value !== leaf),
        };
    });
    nodes[leafNode(leaf, tree.leafCount)] = undefined;
    for (const parent of directPath(leaf, tree.leafCount)) {
        nodes[parent] = undefined;
    }
    return { leafCount: tree.leafCount, nodes };
}

function hashNode(tree: PublicTree, nodeIndex: number, memo: Map<number, Uint8Array>): Uint8Array {
    const existing = memo.get(nodeIndex);
    if (existing !== undefined) {
        return existing;
    }
    const node = tree.nodes[nodeIndex];
    const header = concatBytes(TREE_HASH_DOMAIN, encodeUint32(nodeIndex));
    let result: Uint8Array;
    if (nodeLevel(nodeIndex) === 0) {
        result =
            node?.type === "leaf"
                ? hash(header, new Uint8Array([1]), node.encryptionKey, node.signatureKey)
                : hash(header, new Uint8Array([0]));
    } else {
        const leftHash = hashNode(tree, leftChild(nodeIndex), memo);
        const rightHash = hashNode(tree, rightChild(nodeIndex), memo);
        result =
            node?.type === "parent"
                ? hash(
                      header,
                      new Uint8Array([2]),
                      node.encryptionKey,
                      encodeUint32(node.unmergedLeaves.length),
                      ...node.unmergedLeaves.map(encodeUint32),
                      leftHash,
                      rightHash,
                  )
                : hash(header, new Uint8Array([0]), leftHash, rightHash);
    }
    memo.set(nodeIndex, result);
    return result;
}

/** Hash the complete public tree, including blanks and unmerged leaves. */
export function treeHash(tree: PublicTree): Uint8Array {
    validateLeafCount(tree.leafCount);
    if (tree.nodes.length !== treeWidth(tree.leafCount)) {
        throw new Error("Invalid TreeKEM public tree width");
    }
    return hashNode(tree, treeRoot(tree.leafCount), new Map());
}

/** Validate the complete public tree and its RFC unmerged-leaf invariants. */
export function validateTree(tree: PublicTree, requireConnected: boolean = true): void {
    validateLeafCount(tree.leafCount);
    if (tree.nodes.length !== treeWidth(tree.leafCount)) {
        throw new Error("Invalid TreeKEM public tree width");
    }
    const encryptionKeys = new Set<string>();
    const signatureKeys = new Set<string>();
    let occupied = 0;
    for (let index = 0; index < tree.nodes.length; index += 1) {
        const node = tree.nodes[index];
        if (node === undefined) {
            continue;
        }
        if ((node.type === "leaf") !== (nodeLevel(index) === 0)) {
            throw new Error("TreeKEM node type does not match its position");
        }
        const encryptionKey = canonicalizePublicKey(node.encryptionKey);
        const encryptionId = byteIdentifier(encryptionKey);
        if (encryptionKeys.has(encryptionId)) {
            throw new Error("TreeKEM tree reuses an encryption key");
        }
        encryptionKeys.add(encryptionId);
        if (node.type === "leaf") {
            occupied += 1;
            if (node.signatureKey.length !== 32) {
                throw new Error("Invalid TreeKEM signature public key");
            }
            const signatureId = byteIdentifier(node.signatureKey);
            if (signatureKeys.has(signatureId)) {
                throw new Error("TreeKEM tree reuses a signature key");
            }
            signatureKeys.add(signatureId);
            continue;
        }
        let previous = -1;
        for (const leaf of node.unmergedLeaves) {
            const leafValue = tree.nodes[leafNode(leaf, tree.leafCount)];
            const ancestry = directPath(leaf, tree.leafCount);
            const parentPosition = ancestry.indexOf(index);
            if (leaf <= previous || leafValue?.type !== "leaf" || parentPosition < 0) {
                throw new Error("Invalid TreeKEM unmerged-leaf list");
            }
            for (let pathIndex = 0; pathIndex < parentPosition; pathIndex += 1) {
                const intermediate = tree.nodes[ancestry[pathIndex]!];
                if (
                    intermediate?.type === "parent" &&
                    !intermediate.unmergedLeaves.includes(leaf)
                ) {
                    throw new Error("Invalid TreeKEM unmerged-leaf ancestry");
                }
            }
            previous = leaf;
        }
    }
    if (occupied === 0) {
        throw new Error("TreeKEM tree has no members");
    }
    if (
        requireConnected &&
        occupied > 1 &&
        tree.nodes[treeRoot(tree.leafCount)]?.type !== "parent"
    ) {
        throw new Error("TreeKEM public tree has a blank root");
    }
    treeHash(tree);
}
