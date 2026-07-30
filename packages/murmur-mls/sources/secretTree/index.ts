import { zeroBytes } from "@murmur/core";
import {
    MLS_AEAD_KEY_LENGTH,
    MLS_AEAD_NONCE_LENGTH,
    MLS_HASH_LENGTH,
    mlsExpandWithLabel,
} from "../cipherSuite/index.js";
import { encodeUint32 } from "../encoding/index.js";
import { leafNode, leftChild, parentNode, rightChild, treeRoot } from "../tree/index.js";
import type { MlsGenerationKey, MlsRatchetType } from "./types.js";

export type { MlsGenerationKey, MlsRatchetType } from "./types.js";

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
