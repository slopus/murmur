import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsCommitMember } from "../commit/index.js";
import type { MlsKeyPackage } from "../keyPackage/index.js";
import type { MlsEpochSecrets } from "../keySchedule/index.js";
import type { OpenedMlsWelcome } from "../welcome/index.js";

/** Public member data needed to authenticate one MLS epoch. */
export interface MlsEpochMember {
    readonly signatureKey: Uint8Array;
    readonly encryptionKey?: Uint8Array;
}

/** Inputs for taking ownership of a fully authenticated RFC 9420 epoch. */
export interface CreateMlsEpochOptions {
    readonly context: MlsGroupContext;
    readonly secrets: MlsEpochSecrets;
    readonly members: readonly (MlsEpochMember | undefined)[];
    readonly localLeaf: number;
    readonly localSigningSecretKey: Uint8Array;
    readonly interimTranscriptHash?: Uint8Array;
}

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
    commit(): import("./index.js").MlsEpochState;
    cancel(): void;
}

/** Prepared add-only transition; the current epoch remains active. */
export interface PreparedMlsAddEpoch {
    readonly commit: Uint8Array;
    readonly welcome: Uint8Array;
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
