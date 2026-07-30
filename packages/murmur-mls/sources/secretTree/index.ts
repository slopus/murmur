import { zeroBytes } from "@murmur/core";
import {
    MLS_AEAD_KEY_LENGTH,
    MLS_AEAD_NONCE_LENGTH,
    MLS_HASH_LENGTH,
    mlsExpandWithLabel,
} from "../cipherSuite/index.js";
import { encodeUint32 } from "../encoding/index.js";
import { leafNode, leftChild, parentNode, rightChild, treeRoot, treeWidth } from "../tree/index.js";
import type { MlsGenerationKey, MlsRatchetType, MlsSecretTreeState } from "./types.js";

export type {
    MlsGenerationKey,
    MlsRatchetType,
    MlsSecretTreeRatchetState,
    MlsSecretTreeState,
} from "./types.js";

const DEFAULT_MAXIMUM_FORWARD_DISTANCE = 1_000;
const DEFAULT_MAXIMUM_SKIPPED_KEYS = 10_000;
const HARD_MAXIMUM_FORWARD_DISTANCE = 10_000;
const HARD_MAXIMUM_SKIPPED_KEYS = 100_000;
const MAXIMUM_GENERATION = 0xffff_ffff;
const MAXIMUM_SECRET_TREE_LEAVES = 100_000;

interface RatchetState {
    secret: Uint8Array;
    generation: number;
    readonly skipped: Map<number, MlsGenerationKey>;
}

class AsynchronousUseError extends Error {}

function deriveTreeSecret(
    secret: Uint8Array,
    label: string,
    generation: number,
    length: number,
): Uint8Array {
    return mlsExpandWithLabel(secret, label, encodeUint32(generation), length);
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
    return (
        (typeof value === "object" || typeof value === "function") &&
        value !== null &&
        "then" in value &&
        typeof value.then === "function"
    );
}

/** Zero a one-time generation key after its AEAD operation. */
export function destroyMlsGenerationKey(generationKey: MlsGenerationKey): void {
    zeroBytes(generationKey.key);
    zeroBytes(generationKey.nonce);
}

/** Zero every secret contained in a detached Secret Tree snapshot. */
export function destroyMlsSecretTreeState(state: MlsSecretTreeState): void {
    for (const node of state.nodeSecrets) {
        zeroBytes(node.secret);
    }
    for (const ratchet of state.ratchets) {
        zeroBytes(ratchet.secret);
        for (const skipped of ratchet.skipped) {
            destroyMlsGenerationKey(skipped);
        }
    }
}

function nodePathToRoot(node: number, leafCount: number): readonly number[] {
    const root = treeRoot(leafCount);
    const path = [node];
    let current = node;
    while (current !== root) {
        current = parentNode(current, leafCount);
        path.push(current);
    }
    return path;
}

/**
 * Stateful RFC 9420 Secret Tree for one epoch.
 *
 * Every generation is returned at most once. Future generations may be opened
 * out of order up to the configured forward-distance limit.
 */
export class MlsSecretTree {
    readonly #leafCount: number;
    readonly #maximumForwardDistance: number;
    readonly #maximumSkippedKeys: number;
    readonly #nodeSecrets = new Map<number, Uint8Array>();
    readonly #ratchets = new Map<string, RatchetState>();
    #skippedKeyCount = 0;
    #destroyed = false;

    constructor(
        encryptionSecret: Uint8Array,
        leafCount: number,
        maximumForwardDistance: number = DEFAULT_MAXIMUM_FORWARD_DISTANCE,
        maximumSkippedKeys: number = DEFAULT_MAXIMUM_SKIPPED_KEYS,
    ) {
        if (encryptionSecret.length !== MLS_HASH_LENGTH) {
            throw new Error("MLS encryption secret must be 32 bytes");
        }
        if (
            !Number.isSafeInteger(leafCount) ||
            leafCount < 1 ||
            leafCount > MAXIMUM_SECRET_TREE_LEAVES
        ) {
            throw new Error("Invalid MLS Secret Tree leaf count");
        }
        if (
            !Number.isSafeInteger(maximumForwardDistance) ||
            maximumForwardDistance < 0 ||
            maximumForwardDistance > HARD_MAXIMUM_FORWARD_DISTANCE
        ) {
            throw new Error("Invalid MLS ratchet forward-distance limit");
        }
        if (
            !Number.isSafeInteger(maximumSkippedKeys) ||
            maximumSkippedKeys < 1 ||
            maximumSkippedKeys > HARD_MAXIMUM_SKIPPED_KEYS
        ) {
            throw new Error("Invalid MLS skipped-key budget");
        }
        this.#leafCount = leafCount;
        this.#maximumForwardDistance = maximumForwardDistance;
        this.#maximumSkippedKeys = maximumSkippedKeys;
        this.#nodeSecrets.set(treeRoot(leafCount), encryptionSecret.slice());
    }

    /** Reconstruct a structurally validated mutable Secret Tree snapshot. */
    static fromState(state: MlsSecretTreeState): MlsSecretTree {
        const placeholder = new Uint8Array(MLS_HASH_LENGTH);
        const tree = new MlsSecretTree(
            placeholder,
            state.leafCount,
            state.maximumForwardDistance,
            state.maximumSkippedKeys,
        );
        for (const secret of tree.#nodeSecrets.values()) {
            zeroBytes(secret);
        }
        tree.#nodeSecrets.clear();
        try {
            const width = treeWidth(state.leafCount);
            const cachedNodes = new Set<number>();
            for (const entry of state.nodeSecrets) {
                if (
                    !Number.isSafeInteger(entry.node) ||
                    entry.node < 0 ||
                    entry.node >= width ||
                    entry.secret.length !== MLS_HASH_LENGTH ||
                    cachedNodes.has(entry.node)
                ) {
                    throw new Error("Invalid MLS Secret Tree node snapshot");
                }
                cachedNodes.add(entry.node);
                tree.#nodeSecrets.set(entry.node, entry.secret.slice());
            }
            for (const node of cachedNodes) {
                if (
                    nodePathToRoot(node, state.leafCount)
                        .slice(1)
                        .some((ancestor) => cachedNodes.has(ancestor))
                ) {
                    throw new Error("Overlapping MLS Secret Tree node snapshot");
                }
            }

            const ratchetKeys = new Set<string>();
            const ratchetedSenders = new Set<number>();
            for (const snapshot of state.ratchets) {
                if (
                    (snapshot.type !== "handshake" && snapshot.type !== "application") ||
                    !Number.isSafeInteger(snapshot.generation) ||
                    snapshot.generation < 0 ||
                    snapshot.generation > MAXIMUM_GENERATION + 1 ||
                    snapshot.secret.length !== MLS_HASH_LENGTH
                ) {
                    throw new Error("Invalid MLS sender-ratchet snapshot");
                }
                leafNode(snapshot.sender, state.leafCount);
                const key = `${snapshot.sender}/${snapshot.type}`;
                if (ratchetKeys.has(key)) {
                    throw new Error("Duplicate MLS sender-ratchet snapshot");
                }
                ratchetKeys.add(key);
                ratchetedSenders.add(snapshot.sender);
                const skipped = new Map<number, MlsGenerationKey>();
                for (const generationKey of snapshot.skipped) {
                    if (
                        generationKey.sender !== snapshot.sender ||
                        generationKey.type !== snapshot.type ||
                        !Number.isSafeInteger(generationKey.generation) ||
                        generationKey.generation < 0 ||
                        generationKey.generation >= snapshot.generation ||
                        generationKey.key.length !== MLS_AEAD_KEY_LENGTH ||
                        generationKey.nonce.length !== MLS_AEAD_NONCE_LENGTH ||
                        skipped.has(generationKey.generation)
                    ) {
                        throw new Error("Invalid MLS skipped-key snapshot");
                    }
                    skipped.set(generationKey.generation, {
                        sender: generationKey.sender,
                        type: generationKey.type,
                        generation: generationKey.generation,
                        key: generationKey.key.slice(),
                        nonce: generationKey.nonce.slice(),
                    });
                    tree.#skippedKeyCount += 1;
                }
                if (tree.#skippedKeyCount > state.maximumSkippedKeys) {
                    throw new Error("MLS skipped-key snapshot exceeds its budget");
                }
                tree.#ratchets.set(key, {
                    secret: snapshot.secret.slice(),
                    generation: snapshot.generation,
                    skipped,
                });
            }
            for (const sender of ratchetedSenders) {
                if (
                    !ratchetKeys.has(`${sender}/handshake`) ||
                    !ratchetKeys.has(`${sender}/application`)
                ) {
                    throw new Error("Incomplete MLS sender-ratchet snapshot");
                }
            }
            for (let sender = 0; sender < state.leafCount; sender += 1) {
                const coveringSecrets = nodePathToRoot(
                    leafNode(sender, state.leafCount),
                    state.leafCount,
                ).filter((node) => cachedNodes.has(node)).length;
                if (
                    (ratchetedSenders.has(sender) && coveringSecrets !== 0) ||
                    (!ratchetedSenders.has(sender) && coveringSecrets !== 1)
                ) {
                    throw new Error("MLS Secret Tree frontier snapshot is inconsistent");
                }
            }
            return tree;
        } catch (error: unknown) {
            tree.destroy();
            throw error;
        }
    }

    /** Copy all sensitive mutable state for durable local persistence. */
    snapshot(): MlsSecretTreeState {
        this.#ensureActive();
        return {
            leafCount: this.#leafCount,
            maximumForwardDistance: this.#maximumForwardDistance,
            maximumSkippedKeys: this.#maximumSkippedKeys,
            nodeSecrets: [...this.#nodeSecrets]
                .sort(([left], [right]) => left - right)
                .map(([node, secret]) => ({ node, secret: secret.slice() })),
            ratchets: [...this.#ratchets]
                .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
                .map(([key, state]) => {
                    const separator = key.indexOf("/");
                    const sender = Number(key.slice(0, separator));
                    const type = key.slice(separator + 1) as MlsRatchetType;
                    return {
                        sender,
                        type,
                        secret: state.secret.slice(),
                        generation: state.generation,
                        skipped: [...state.skipped.values()]
                            .sort((left, right) => left.generation - right.generation)
                            .map((generationKey) => ({
                                sender: generationKey.sender,
                                type: generationKey.type,
                                generation: generationKey.generation,
                                key: generationKey.key.slice(),
                                nonce: generationKey.nonce.slice(),
                            })),
                    };
                }),
        };
    }

    /** Derive the next outbound key for one sender and content type. */
    next(sender: number, type: MlsRatchetType): MlsGenerationKey {
        this.#ensureActive();
        const state = this.#ratchet(sender, type);
        return this.#advance(sender, type, state);
    }

    /** Take one inbound generation key, retaining bounded skipped generations. */
    take(sender: number, type: MlsRatchetType, generation: number): MlsGenerationKey {
        return this.#take(sender, type, generation, false);
    }

    #take(
        sender: number,
        type: MlsRatchetType,
        generation: number,
        reserveForRollback: boolean,
    ): MlsGenerationKey {
        this.#ensureActive();
        if (
            !Number.isSafeInteger(generation) ||
            generation < 0 ||
            generation > MAXIMUM_GENERATION
        ) {
            throw new Error("Invalid MLS sender generation");
        }
        const state = this.#ratchet(sender, type);
        if (generation < state.generation) {
            const skipped = state.skipped.get(generation);
            if (skipped === undefined) {
                throw new Error("MLS sender generation was already consumed");
            }
            state.skipped.delete(generation);
            this.#skippedKeyCount -= 1;
            return skipped;
        }
        const distance = generation - state.generation;
        if (distance > this.#maximumForwardDistance) {
            throw new Error("MLS sender generation is too far in the future");
        }
        const requiredSlots = distance + (reserveForRollback ? 1 : 0);
        if (this.#skippedKeyCount + requiredSlots > this.#maximumSkippedKeys) {
            throw new Error("MLS skipped-key budget exhausted");
        }
        for (;;) {
            const derived = this.#advance(sender, type, state);
            if (derived.generation === generation) {
                return derived;
            }
            state.skipped.set(derived.generation, derived);
            this.#skippedKeyCount += 1;
        }
    }

    /**
     * Use an inbound key transactionally.
     *
     * The callback must be synchronous. A thrown authentication/decoding error
     * restores the generation so an invalid ciphertext cannot burn a valid key.
     */
    use<T>(
        sender: number,
        type: MlsRatchetType,
        generation: number,
        operation: (generationKey: MlsGenerationKey) => T,
    ): T {
        const generationKey = this.#take(sender, type, generation, true);
        try {
            const result = operation(generationKey);
            if (isPromiseLike(result)) {
                destroyMlsGenerationKey(generationKey);
                throw new AsynchronousUseError("MLS Secret Tree use callback must be synchronous");
            }
            destroyMlsGenerationKey(generationKey);
            return result;
        } catch (error: unknown) {
            if (error instanceof AsynchronousUseError) {
                throw error;
            }
            const state = this.#ratchet(sender, type);
            if (state.skipped.has(generation)) {
                destroyMlsGenerationKey(generationKey);
                throw new Error("MLS sender generation restoration collision", {
                    cause: error,
                });
            }
            state.skipped.set(generation, generationKey);
            this.#skippedKeyCount += 1;
            throw error;
        }
    }

    /** Destroy all retained epoch secrets and skipped keys. */
    destroy(): void {
        if (this.#destroyed) {
            return;
        }
        this.#destroyed = true;
        for (const secret of this.#nodeSecrets.values()) {
            zeroBytes(secret);
        }
        this.#nodeSecrets.clear();
        for (const state of this.#ratchets.values()) {
            zeroBytes(state.secret);
            for (const generationKey of state.skipped.values()) {
                destroyMlsGenerationKey(generationKey);
            }
            state.skipped.clear();
        }
        this.#ratchets.clear();
        this.#skippedKeyCount = 0;
    }

    #ratchet(sender: number, type: MlsRatchetType): RatchetState {
        if (type !== "handshake" && type !== "application") {
            throw new Error("Invalid MLS ratchet type");
        }
        // `leafNode` supplies the common sender bounds check.
        leafNode(sender, this.#leafCount);
        const key = `${sender}/${type}`;
        const existing = this.#ratchets.get(key);
        if (existing !== undefined) {
            return existing;
        }
        const leafSecret = this.#consumeLeafSecret(sender);
        let handshakeSecret: Uint8Array | undefined;
        let applicationSecret: Uint8Array | undefined;
        try {
            handshakeSecret = deriveTreeSecret(leafSecret, "handshake", 0, MLS_HASH_LENGTH);
            applicationSecret = deriveTreeSecret(leafSecret, "application", 0, MLS_HASH_LENGTH);
        } catch (error: unknown) {
            if (handshakeSecret !== undefined) {
                zeroBytes(handshakeSecret);
            }
            if (applicationSecret !== undefined) {
                zeroBytes(applicationSecret);
            }
            throw error;
        } finally {
            zeroBytes(leafSecret);
        }
        if (handshakeSecret === undefined || applicationSecret === undefined) {
            throw new Error("MLS sender ratchet derivation failed");
        }
        const handshake: RatchetState = {
            secret: handshakeSecret,
            generation: 0,
            skipped: new Map(),
        };
        const application: RatchetState = {
            secret: applicationSecret,
            generation: 0,
            skipped: new Map(),
        };
        this.#ratchets.set(`${sender}/handshake`, handshake);
        this.#ratchets.set(`${sender}/application`, application);
        return type === "handshake" ? handshake : application;
    }

    #consumeLeafSecret(sender: number): Uint8Array {
        const root = treeRoot(this.#leafCount);
        const target = leafNode(sender, this.#leafCount);
        const path = [target];
        let node = target;
        while (node !== root) {
            node = parentNode(node, this.#leafCount);
            path.push(node);
        }
        path.reverse();

        let cachedPathIndex = -1;
        for (let index = path.length - 1; index >= 0; index -= 1) {
            if (this.#nodeSecrets.has(path[index] ?? -1)) {
                cachedPathIndex = index;
                break;
            }
        }
        if (cachedPathIndex < 0) {
            throw new Error("MLS leaf secret was already consumed");
        }
        let currentNode = path[cachedPathIndex] ?? root;
        let secret = this.#nodeSecrets.get(currentNode);
        this.#nodeSecrets.delete(currentNode);
        if (secret === undefined) {
            throw new Error("MLS node secret cache is inconsistent");
        }

        for (let index = cachedPathIndex + 1; index < path.length; index += 1) {
            const selectedChild = path[index] ?? target;
            const left = leftChild(currentNode);
            const right = rightChild(currentNode, this.#leafCount);
            let leftSecret: Uint8Array | undefined;
            let rightSecret: Uint8Array | undefined;
            try {
                leftSecret = deriveTreeSecret(secret, "tree", left, MLS_HASH_LENGTH);
                rightSecret = deriveTreeSecret(secret, "tree", right, MLS_HASH_LENGTH);
            } catch (error: unknown) {
                if (leftSecret !== undefined) {
                    zeroBytes(leftSecret);
                }
                if (rightSecret !== undefined) {
                    zeroBytes(rightSecret);
                }
                throw error;
            } finally {
                zeroBytes(secret);
            }
            if (selectedChild === left) {
                this.#nodeSecrets.set(right, rightSecret);
                secret = leftSecret;
            } else if (selectedChild === right) {
                this.#nodeSecrets.set(left, leftSecret);
                secret = rightSecret;
            } else {
                zeroBytes(leftSecret);
                zeroBytes(rightSecret);
                throw new Error("MLS Secret Tree path is inconsistent");
            }
            currentNode = selectedChild;
        }
        return secret;
    }

    #advance(sender: number, type: MlsRatchetType, state: RatchetState): MlsGenerationKey {
        if (state.generation > MAXIMUM_GENERATION) {
            throw new Error("MLS sender generation exhausted");
        }
        const generation = state.generation;
        const key = deriveTreeSecret(state.secret, "key", generation, MLS_AEAD_KEY_LENGTH);
        let nonce: Uint8Array;
        try {
            nonce = deriveTreeSecret(state.secret, "nonce", generation, MLS_AEAD_NONCE_LENGTH);
        } catch (error: unknown) {
            zeroBytes(key);
            throw error;
        }
        let nextSecret: Uint8Array;
        try {
            nextSecret = deriveTreeSecret(state.secret, "secret", generation, MLS_HASH_LENGTH);
        } catch (error: unknown) {
            zeroBytes(key);
            zeroBytes(nonce);
            throw error;
        }
        zeroBytes(state.secret);
        state.secret = nextSecret;
        state.generation += 1;
        return { sender, generation, type, key, nonce };
    }

    #ensureActive(): void {
        if (this.#destroyed) {
            throw new Error("MLS Secret Tree was destroyed");
        }
    }
}
