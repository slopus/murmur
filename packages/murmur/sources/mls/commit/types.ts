import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsKeyPackage } from "../keyPackage/index.js";
import type { MlsEpochSecrets } from "../keySchedule/index.js";
import type { MlsRatchetTree } from "../ratchetTree/index.js";
import type { MlsTreePrivateKey, MlsUpdatePath } from "../updatePath/index.js";

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
