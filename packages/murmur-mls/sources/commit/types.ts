import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsKeyPackage } from "../keyPackage/index.js";
import type { MlsEpochSecrets } from "../keySchedule/index.js";
import type { MlsRatchetTree } from "../ratchetTree/index.js";
import type { MlsTreePrivateKey, MlsUpdatePath } from "../updatePath/index.js";

/** Public member information used while applying an add-only Commit. */
export interface MlsCommitMember {
    readonly signatureKey: Uint8Array;
    readonly encryptionKey: Uint8Array;
}

/** Parsed RFC 9420 PublicMessage containing an inline add-only Commit. */
export interface MlsAddCommitMessage {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly sender: number;
    readonly authenticatedData: Uint8Array;
    readonly additions: readonly MlsKeyPackage[];
    readonly signature: Uint8Array;
    readonly confirmationTag: Uint8Array;
    readonly membershipTag: Uint8Array;
}

/** Inputs for creating an RFC 9420 add-only Commit without an UpdatePath. */
export interface CreateMlsAddCommitOptions {
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly nextInitSecret: Uint8Array;
    readonly membershipKey: Uint8Array;
    readonly members: readonly (MlsCommitMember | undefined)[];
    readonly sender: number;
    readonly signingSecretKey: Uint8Array;
    readonly additions: readonly MlsKeyPackage[];
    /**
     * Validate a candidate external tree after exact leftmost-blank insertion.
     * The validator must check all LeafNodes, leaf and parent encryption-key
     * uniqueness, parent hashes, node placement, and the computed tree hash.
     */
    readonly validateExternalTree: (
        additions: readonly MlsKeyPackage[],
        nextMembers: readonly (MlsCommitMember | undefined)[],
    ) => Uint8Array;
    readonly authenticatedData?: Uint8Array;
}

/** Inputs for authenticating and applying an add-only Commit. */
export interface OpenMlsAddCommitOptions {
    readonly message: Uint8Array;
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly nextInitSecret: Uint8Array;
    readonly membershipKey: Uint8Array;
    readonly members: readonly (MlsCommitMember | undefined)[];
    /**
     * Validate a candidate external tree without mutating the active tree.
     * Validation covers all LeafNodes, leaf and parent encryption-key
     * uniqueness, parent hashes, node placement, and the computed tree hash.
     * The caller commits its candidate tree only after this function succeeds.
     */
    readonly validateExternalTree: (
        additions: readonly MlsKeyPackage[],
        nextMembers: readonly (MlsCommitMember | undefined)[],
    ) => Uint8Array;
}

/** Authenticated state produced for the next epoch. */
export interface MlsAppliedAddCommit {
    readonly message: MlsAddCommitMessage;
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly secrets: MlsEpochSecrets;
    readonly members: readonly (MlsCommitMember | undefined)[];
}

/** Committer result, including the Welcome addressed to newly added members. */
export interface MlsCreatedAddCommit extends MlsAppliedAddCommit {
    readonly commit: Uint8Array;
    readonly welcome: Uint8Array;
}

/** Inline Add or Remove proposal supported by the full TreeKEM Commit profile. */
export type MlsTreeCommitProposal =
    | { readonly type: "add"; readonly keyPackage: MlsKeyPackage }
    | { readonly type: "remove"; readonly removed: number };

/** RFC PublicMessage Commit containing a mandatory TreeKEM UpdatePath. */
export interface MlsTreeCommitMessage {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly sender: number;
    readonly authenticatedData: Uint8Array;
    readonly proposals: readonly MlsTreeCommitProposal[];
    readonly path: MlsUpdatePath;
    readonly signature: Uint8Array;
    readonly confirmationTag: Uint8Array;
    readonly membershipTag: Uint8Array;
}

/** Inputs shared by full TreeKEM Commit creation and opening. */
export interface MlsTreeCommitState {
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly nextInitSecret: Uint8Array;
    readonly membershipKey: Uint8Array;
    readonly tree: MlsRatchetTree;
    readonly authenticateCredential: (
        leafNode: import("../leafNode/index.js").MlsLeafNode,
        leafIndex: number,
    ) => boolean;
}

/** Create a full RFC Commit with cryptographic Add/Remove transitions. */
export interface CreateMlsTreeCommitOptions extends MlsTreeCommitState {
    readonly sender: number;
    readonly signingSecretKey: Uint8Array;
    readonly proposals: readonly MlsTreeCommitProposal[];
    readonly authenticatedData?: Uint8Array;
}

/** Authenticate and open a full RFC Commit as a retained current member. */
export interface OpenMlsTreeCommitOptions extends MlsTreeCommitState {
    readonly message: Uint8Array;
    readonly localLeaf: number;
    readonly privateKeys: readonly MlsTreePrivateKey[];
}

/** Authenticated next-epoch state from a full TreeKEM Commit. */
export interface MlsAppliedTreeCommit {
    readonly message: MlsTreeCommitMessage;
    readonly context: MlsGroupContext;
    readonly interimTranscriptHash: Uint8Array;
    readonly secrets: MlsEpochSecrets;
    readonly tree: MlsRatchetTree;
    readonly privateKeys: readonly MlsTreePrivateKey[];
    readonly addedLeaves: readonly number[];
    readonly removedLeaves: readonly number[];
}

/** Committer output, plus an optional Welcome when Add proposals are present. */
export interface MlsCreatedTreeCommit extends MlsAppliedTreeCommit {
    readonly commit: Uint8Array;
    readonly welcome?: Uint8Array;
}
