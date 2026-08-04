import type { HpkeCiphertext, HpkeKeyPair } from "../cipherSuite/index.js";
import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsLeafNode } from "../leafNode/index.js";
import type { MlsRatchetTree } from "../ratchetTree/index.js";

/** One parent entry in an RFC UpdatePath. */
export interface MlsUpdatePathNode {
    readonly encryptionKey: Uint8Array;
    readonly encryptedPathSecrets: readonly HpkeCiphertext[];
}

/** RFC 9420 UpdatePath. */
export interface MlsUpdatePath {
    readonly leafNode: MlsLeafNode;
    readonly nodes: readonly MlsUpdatePathNode[];
}

/** One private TreeKEM key retained for the local member. */
export interface MlsTreePrivateKey {
    readonly node: number;
    readonly keyPair: HpkeKeyPair;
}

/** Inputs for generating and encrypting an UpdatePath. */
export interface CreateMlsUpdatePathOptions {
    readonly tree: MlsRatchetTree;
    readonly sender: number;
    readonly signingSecretKey: Uint8Array;
    readonly provisionalContext: Omit<MlsGroupContext, "treeHash">;
    readonly authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
    readonly excludedNewLeaves?: ReadonlySet<number>;
    /** Deterministic test hook; production callers omit it. */
    readonly leafSecret?: Uint8Array;
    /** Deterministic test hook; production callers omit it. */
    readonly firstPathSecret?: Uint8Array;
}

/** Inputs for authenticating and decrypting an UpdatePath. */
export interface OpenMlsUpdatePathOptions {
    readonly tree: MlsRatchetTree;
    readonly sender: number;
    readonly path: MlsUpdatePath;
    readonly provisionalContext: Omit<MlsGroupContext, "treeHash">;
    readonly localLeaf: number;
    readonly privateKeys: readonly MlsTreePrivateKey[];
    readonly excludedNewLeaves?: ReadonlySet<number>;
    readonly authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
}

/** Inputs for authenticating only the public portion of an UpdatePath. */
export type ValidateMlsUpdatePathOptions = Omit<
    OpenMlsUpdatePathOptions,
    "localLeaf" | "privateKeys"
>;

/** Authenticated public-tree result available even to a removed member. */
export interface MlsValidatedUpdatePath {
    readonly tree: MlsRatchetTree;
    readonly context: MlsGroupContext;
}

/** New TreeKEM private state and commit secret after an UpdatePath. */
export interface MlsUpdatePathResult {
    readonly tree: MlsRatchetTree;
    readonly path: MlsUpdatePath;
    readonly context: MlsGroupContext;
    readonly commitSecret: Uint8Array;
    readonly privateKeys: readonly MlsTreePrivateKey[];
    readonly pathSecrets: readonly {
        readonly node: number;
        readonly secret: Uint8Array;
    }[];
}

/** Inputs for reconstructing a Welcome joiner's private TreeKEM path. */
export interface DeriveMlsWelcomePrivateKeysOptions {
    readonly tree: MlsRatchetTree;
    readonly groupId: Uint8Array;
    readonly sender: number;
    readonly localLeaf: number;
    readonly leafKeyPair: HpkeKeyPair;
    readonly pathSecret?: Uint8Array;
    readonly authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
}
