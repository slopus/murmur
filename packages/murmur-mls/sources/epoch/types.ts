import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsCommitMember, MlsTreeCommitProposal } from "../commit/index.js";
import type { MlsKeyPackage } from "../keyPackage/index.js";
import type { MlsEpochSecrets } from "../keySchedule/index.js";
import type { MlsLeafNode } from "../leafNode/index.js";
import type { MlsRatchetTree } from "../ratchetTree/index.js";
import type { HpkeKeyPair } from "../cipherSuite/index.js";
import type { MlsTreePrivateKey } from "../updatePath/index.js";
import type { OpenedMlsWelcome } from "../welcome/index.js";
import type { MlsSecretTreeState } from "../secretTree/index.js";

/** Public member data needed to authenticate one MLS epoch. */
export interface MlsEpochMember {
    readonly signatureKey: Uint8Array;
    readonly encryptionKey?: Uint8Array;
}

/** Shared inputs for taking ownership of one authenticated RFC 9420 epoch. */
interface CreateMlsEpochBaseOptions {
    readonly context: MlsGroupContext;
    readonly secrets: MlsEpochSecrets;
    readonly localLeaf: number;
    readonly localSigningSecretKey: Uint8Array;
    readonly interimTranscriptHash?: Uint8Array;
    /** Monotonic local checkpoint generation, restored from durable metadata. */
    readonly persistenceGeneration?: bigint;
    /** Restored mutable ratchet state; consumed only after successful construction. */
    readonly secretTreeState?: MlsSecretTreeState;
}

/** Compatibility inputs for an epoch without integrated TreeKEM state. */
export interface CreateLegacyMlsEpochOptions extends CreateMlsEpochBaseOptions {
    readonly members: readonly (MlsEpochMember | undefined)[];
    readonly tree?: never;
    readonly privateKeys?: never;
    readonly authenticateCredential?: never;
}

/** Inputs for an epoch which owns its authenticated public and private TreeKEM state. */
export interface CreateTreeMlsEpochOptions extends CreateMlsEpochBaseOptions {
    readonly tree: MlsRatchetTree;
    readonly privateKeys: readonly MlsTreePrivateKey[];
    readonly authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
    readonly members?: never;
}

/** Supported epoch construction modes. */
export type CreateMlsEpochOptions = CreateLegacyMlsEpochOptions | CreateTreeMlsEpochOptions;

/** Transactional external ratchet-tree candidate for one epoch transition. */
export interface MlsExternalTreeTransition {
    readonly treeHash: Uint8Array;
    commit(): void;
    cancel(): void;
}

/** External RFC ratchet-tree validation used by add-only epoch transitions. */
export type MlsAddTreeValidator = (
    additions: readonly MlsKeyPackage[],
    nextMembers: readonly (MlsCommitMember | undefined)[],
) => MlsExternalTreeTransition;

/** Explicit lifecycle for a staged next epoch and external tree. */
export interface MlsEpochTransition {
    /** Authenticated MLS leaf which authored this transition. */
    readonly sender: number;
    /** Monotonic generation of the staged next-epoch checkpoint. */
    readonly persistenceGeneration: bigint;
    /** Serialize the staged next epoch before publishing its Commit. */
    serialize(): Uint8Array;
    commit(): import("./index.js").MlsEpochState;
    cancel(): void;
}

/** Prepared add-only transition; the current epoch remains active. */
export interface PreparedMlsAddEpoch {
    readonly commit: Uint8Array;
    readonly welcome: Uint8Array;
    readonly transition: MlsEpochTransition;
}

/** Prepared full TreeKEM Commit; adoption remains transactional until publish succeeds. */
export interface PreparedMlsTreeEpoch {
    readonly commit: Uint8Array;
    readonly welcome?: Uint8Array;
    readonly tree: MlsRatchetTree;
    readonly addedLeaves: readonly number[];
    readonly removedLeaves: readonly number[];
    readonly transition: MlsEpochTransition;
}

/** Authenticated external-tree leaf view needed to adopt a Welcome. */
export interface MlsValidatedWelcomeTree {
    readonly treeHash: Uint8Array;
    readonly members: readonly (MlsEpochMember | undefined)[];
    readonly localLeaf: number;
}

/** Inputs for safely adopting an already authenticated Welcome. */
export interface CreateMlsEpochFromWelcomeOptions {
    readonly opened: OpenedMlsWelcome;
    readonly tree: MlsValidatedWelcomeTree;
    readonly localSigningSecretKey: Uint8Array;
}

/** Inputs for adopting Welcome directly into integrated TreeKEM epoch state. */
export interface CreateMlsTreeEpochFromWelcomeOptions {
    readonly opened: OpenedMlsWelcome;
    readonly tree: MlsRatchetTree;
    readonly localLeaf: number;
    readonly leafKeyPair: HpkeKeyPair;
    readonly localSigningSecretKey: Uint8Array;
    readonly authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
}

/** Full TreeKEM proposals accepted by integrated epoch transitions. */
export type MlsEpochCommitProposal = MlsTreeCommitProposal;

/** External key binding and credential policy used to restore a durable epoch. */
export interface DeserializeMlsEpochOptions {
    readonly localSigningSecretKey: Uint8Array;
    readonly authenticateCredential?: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
    /**
     * Smallest checkpoint generation accepted from rollback-resistant metadata.
     *
     * Applications should update this metadata atomically with the serialized
     * epoch and any event or application state produced from it.
     */
    readonly minimumPersistenceGeneration: bigint;
}
