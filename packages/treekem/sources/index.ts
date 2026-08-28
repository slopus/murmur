import {
    applyTreeKemPacket,
    createTreeKemGroup,
    createTreeKemKeyPair,
    createTreeKemUpdate,
    joinTreeKemGroup,
} from "./impl/protocol.js";
import type {
    TreeKemChanges,
    TreeKemKeyPair,
    TreeKemResult,
    TreeKemUpdateResult,
} from "./types.js";

export type {
    TreeKemChanges,
    TreeKemKeyPair,
    TreeKemResult,
    TreeKemUpdateResult,
} from "./types.js";

/** Generate a one-use admission key pair for one group membership. */
export function keyPair(): TreeKemKeyPair {
    return createTreeKemKeyPair();
}

/** Create a one-member TreeKEM group without retaining hidden package state. */
export function create(memberKeyPair: TreeKemKeyPair): TreeKemResult {
    return createTreeKemGroup(memberKeyPair);
}

/**
 * Update the local path and atomically apply optional batched membership changes.
 *
 * Removals are applied before additions. `publicWelcomes` is parallel to
 * `changes.add`.
 */
export function update(secretState: Uint8Array, changes: TreeKemChanges = {}): TreeKemUpdateResult {
    return createTreeKemUpdate(secretState, changes);
}

/** Authenticate and apply another current member's TreeKEM update. */
export function apply(secretState: Uint8Array, publicPacket: Uint8Array): TreeKemResult {
    return applyTreeKemPacket(secretState, publicPacket);
}

/** Join a TreeKEM group using a Welcome and its one-use admission secret. */
export function join(secretKey: Uint8Array, publicWelcome: Uint8Array): TreeKemResult {
    return joinTreeKemGroup(secretKey, publicWelcome);
}

/** Overwrite caller-owned state, private keys, or shared secrets in place. */
export function destroy(...values: readonly Uint8Array[]): void {
    for (const value of values) {
        value.fill(0);
    }
}
