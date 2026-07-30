const MAXIMUM_LEAVES = 1_000_000;

function validateLeafCount(leafCount: number): void {
    if (!Number.isSafeInteger(leafCount) || leafCount < 1 || leafCount > MAXIMUM_LEAVES) {
        throw new Error(`MLS leaf count must be between 1 and ${MAXIMUM_LEAVES}`);
    }
}

function validateNode(node: number, leafCount: number): void {
    validateLeafCount(leafCount);
    if (!Number.isSafeInteger(node) || node < 0 || node >= treeWidth(leafCount)) {
        throw new Error("Node is outside the MLS tree");
    }
}

/** Number of nodes in a left-balanced tree. */
export function treeWidth(leafCount: number): number {
    validateLeafCount(leafCount);
    return 2 * leafCount - 1;
}

/** Convert a zero-based leaf position to its even node index. */
export function leafNode(leafIndex: number, leafCount: number): number {
    validateLeafCount(leafCount);
    if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= leafCount) {
        throw new Error("Leaf is outside the MLS tree");
    }
    return 2 * leafIndex;
}

/** RFC 9420 node level: count consecutive one bits from the least significant bit. */
export function nodeLevel(node: number): number {
    if (!Number.isSafeInteger(node) || node < 0) {
        throw new Error("MLS node index must be a non-negative safe integer");
    }
    let value = BigInt(node);
    let level = 0;
    while ((value & 1n) === 1n) {
        level += 1;
        value >>= 1n;
    }
    return level;
}

/** Root node index for a tree with the given number of leaves. */
export function treeRoot(leafCount: number): number {
    const width = treeWidth(leafCount);
    let power = 1;
    while (power * 2 <= width) {
        power *= 2;
    }
    return power - 1;
}

/** Left child of a parent node. */
export function leftChild(node: number): number {
    const level = nodeLevel(node);
    if (level === 0) {
        throw new Error("A leaf has no left child");
    }
    return Number(BigInt(node) ^ (1n << BigInt(level - 1)));
}

/** Right child, adjusted to the shape of a non-perfect tree. */
export function rightChild(node: number, leafCount: number): number {
    validateNode(node, leafCount);
    const level = nodeLevel(node);
    if (level === 0) {
        throw new Error("A leaf has no right child");
    }
    const width = treeWidth(leafCount);
    let right = Number(BigInt(node) ^ (3n << BigInt(level - 1)));
    while (right >= width) {
        right = leftChild(right);
    }
    return right;
}

function parentStep(node: number): number {
    const level = nodeLevel(node);
    const value = BigInt(node);
    return Number((value | (1n << BigInt(level))) & ~(1n << BigInt(level + 1)));
}

/** Parent node in a left-balanced tree. */
export function parentNode(node: number, leafCount: number): number {
    validateNode(node, leafCount);
    const root = treeRoot(leafCount);
    if (node === root) {
        throw new Error("The root has no parent");
    }
    const width = treeWidth(leafCount);
    let parent = parentStep(node);
    while (parent >= width) {
        parent = parentStep(parent);
    }
    return parent;
}

/** Sibling node in a left-balanced tree. */
export function siblingNode(node: number, leafCount: number): number {
    const parent = parentNode(node, leafCount);
    return node < parent ? rightChild(parent, leafCount) : leftChild(parent);
}

/** Direct path from a leaf's parent through the root, inclusive. */
export function directPath(leafIndex: number, leafCount: number): readonly number[] {
    let node = leafNode(leafIndex, leafCount);
    const root = treeRoot(leafCount);
    const path: number[] = [];
    while (node !== root) {
        node = parentNode(node, leafCount);
        path.push(node);
    }
    return path;
}

/** Copath siblings corresponding to a leaf's direct path. */
export function copath(leafIndex: number, leafCount: number): readonly number[] {
    let node = leafNode(leafIndex, leafCount);
    const root = treeRoot(leafCount);
    const path: number[] = [];
    while (node !== root) {
        path.push(siblingNode(node, leafCount));
        node = parentNode(node, leafCount);
    }
    return path;
}
