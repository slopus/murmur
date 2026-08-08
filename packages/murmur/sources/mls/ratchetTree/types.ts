/** Public leaf data retained by the RFC ratchet tree. */
export interface MlsRatchetTreeLeaf {
    readonly type: "leaf";
    /** Exact RFC LeafNode encoding used by TreeHashInput. */
    readonly encoded: Uint8Array;
    readonly encryptionKey: Uint8Array;
    readonly signatureKey: Uint8Array;
    /** Present for commit-source leaves installed by an UpdatePath. */
    readonly parentHash?: Uint8Array;
}

/** Public parent data retained by the RFC ratchet tree. */
export interface MlsRatchetTreeParent {
    readonly type: "parent";
    readonly encryptionKey: Uint8Array;
    readonly parentHash: Uint8Array;
    readonly unmergedLeaves: readonly number[];
}

/** One populated public node, or `undefined` for a blank node. */
export type MlsRatchetTreeNode = MlsRatchetTreeLeaf | MlsRatchetTreeParent | undefined;

/** Authentication inputs required for validating an external public tree. */
export interface MlsRatchetTreeValidationOptions {
    readonly groupId: Uint8Array;
    readonly authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
}
import type { MlsLeafNode } from "../leafNode/index.js";
