import { equalBytes, zeroBytes } from "@murmur/core";
import { mlsSignWithLabel, mlsVerifyWithLabel } from "../cipherSuite/index.js";
import { createMlsAddCommit, openMlsAddCommit, type MlsCommitMember } from "../commit/index.js";
import {
    encodeMlsGroupContext,
    updateInterimTranscriptHash,
    type MlsGroupContext,
} from "../groupContext/index.js";
import type { MlsKeyPackage } from "../keyPackage/index.js";
import { destroyMlsEpochSecrets, type MlsEpochSecrets } from "../keySchedule/index.js";
import {
    openMlsApplicationMessage,
    sealMlsApplicationMessage,
    type OpenedMlsApplicationMessage,
} from "../privateMessage/index.js";
import { MlsSecretTree } from "../secretTree/index.js";
import type {
    CreateMlsEpochOptions,
    CreateMlsEpochFromWelcomeOptions,
    MlsAddTreeValidator,
    MlsEpochMember,
    MlsEpochTransition,
    MlsExternalTreeTransition,
    PreparedMlsAddEpoch,
} from "./types.js";

export type {
    CreateMlsEpochOptions,
    CreateMlsEpochFromWelcomeOptions,
    MlsAddTreeValidator,
    MlsEpochMember,
    MlsEpochTransition,
    MlsExternalTreeTransition,
    PreparedMlsAddEpoch,
    MlsValidatedWelcomeTree,
} from "./types.js";

const OWNERSHIP_LABEL = "Murmur Epoch Ownership";
const OWNERSHIP_CONTENT = new Uint8Array();
const MAXIMUM_EPOCH_MEMBERS = 100_000;

function copyContext(context: MlsGroupContext): MlsGroupContext {
    return {
        groupId: context.groupId.slice(),
        epoch: context.epoch,
        treeHash: context.treeHash.slice(),
        confirmedTranscriptHash: context.confirmedTranscriptHash.slice(),
    };
}

function snapshotEpochSecrets(secrets: MlsEpochSecrets): MlsEpochSecrets {
    return {
        joinerSecret: secrets.joinerSecret,
        memberSecret: secrets.memberSecret,
        epochSecret: secrets.epochSecret,
        senderDataSecret: secrets.senderDataSecret,
        encryptionSecret: secrets.encryptionSecret,
        exporterSecret: secrets.exporterSecret,
        epochAuthenticator: secrets.epochAuthenticator,
        externalSecret: secrets.externalSecret,
        confirmationKey: secrets.confirmationKey,
        membershipKey: secrets.membershipKey,
        resumptionPsk: secrets.resumptionPsk,
        nextInitSecret: secrets.nextInitSecret,
    };
}

function epochSecretValues(secrets: MlsEpochSecrets): readonly Uint8Array[] {
    return [
        secrets.joinerSecret,
        secrets.memberSecret,
        secrets.epochSecret,
        secrets.senderDataSecret,
        secrets.encryptionSecret,
        secrets.exporterSecret,
        secrets.epochAuthenticator,
        secrets.externalSecret,
        secrets.confirmationKey,
        secrets.membershipKey,
        secrets.resumptionPsk,
        secrets.nextInitSecret,
    ];
}

function copyEpochSecrets(secrets: MlsEpochSecrets): MlsEpochSecrets {
    const completed: Uint8Array[] = [];
    const copy = (secret: Uint8Array): Uint8Array => {
        const result = secret.slice();
        completed.push(result);
        return result;
    };
    try {
        return {
            joinerSecret: copy(secrets.joinerSecret),
            memberSecret: copy(secrets.memberSecret),
            epochSecret: copy(secrets.epochSecret),
            senderDataSecret: copy(secrets.senderDataSecret),
            encryptionSecret: copy(secrets.encryptionSecret),
            exporterSecret: copy(secrets.exporterSecret),
            epochAuthenticator: copy(secrets.epochAuthenticator),
            externalSecret: copy(secrets.externalSecret),
            confirmationKey: copy(secrets.confirmationKey),
            membershipKey: copy(secrets.membershipKey),
            resumptionPsk: copy(secrets.resumptionPsk),
            nextInitSecret: copy(secrets.nextInitSecret),
        };
    } catch (error: unknown) {
        for (const secret of completed) {
            zeroBytes(secret);
        }
        throw error;
    }
}

class StagedEpochTransition implements MlsEpochTransition {
    readonly #current: MlsEpochState;
    readonly #next: MlsEpochState;
    readonly #tree: MlsExternalTreeTransition;
    readonly #onSettle: () => void;
    #state: "pending" | "committing" | "cancelling" | "settled" = "pending";

    constructor(
        current: MlsEpochState,
        next: MlsEpochState,
        tree: MlsExternalTreeTransition,
        onSettle: () => void,
    ) {
        this.#current = current;
        this.#next = next;
        this.#tree = tree;
        this.#onSettle = onSettle;
    }

    commit(): MlsEpochState {
        this.#ensurePending();
        this.#state = "committing";
        try {
            this.#tree.commit();
        } catch (error: unknown) {
            this.#state = "pending";
            throw error;
        }
        this.#state = "settled";
        this.#onSettle();
        this.#current.destroy();
        return this.#next;
    }

    cancel(): void {
        this.#ensurePending();
        this.#state = "cancelling";
        try {
            this.#tree.cancel();
        } finally {
            try {
                this.#next.destroy();
            } finally {
                this.#state = "settled";
                this.#onSettle();
            }
        }
    }

    #ensurePending(): void {
        if (this.#state !== "pending") {
            throw new Error(`MLS epoch transition is ${this.#state}`);
        }
    }
}

/**
 * Mutable application state for one authenticated RFC 9420 epoch.
 *
 * After successful construction, the instance takes ownership of
 * `options.secrets` by cloning them privately and zeroing every input array.
 * Construction failure leaves ownership with the caller. A Commit transition
 * creates a new instance only after the separate TreeKEM/Commit layer has
 * authenticated the next context and secrets.
 */
export class MlsEpochState {
    readonly #context: MlsGroupContext;
    readonly #secrets: MlsEpochSecrets;
    readonly #members: readonly (MlsEpochMember | undefined)[];
    readonly #localLeaf: number;
    readonly #localSigningSecretKey: Uint8Array;
    readonly #secretTree: MlsSecretTree;
    readonly #interimTranscriptHash: Uint8Array | undefined;
    #destroyed = false;
    #pendingTransition: StagedEpochTransition | undefined;
    #transitionState: "idle" | "preparing" | "staged" = "idle";

    constructor(options: CreateMlsEpochOptions) {
        encodeMlsGroupContext(options.context);
        const inputSecrets = snapshotEpochSecrets(options.secrets);
        if (
            options.members.length === 0 ||
            options.members.length > MAXIMUM_EPOCH_MEMBERS ||
            !Number.isSafeInteger(options.localLeaf) ||
            options.localLeaf < 0 ||
            options.localLeaf >= options.members.length ||
            options.localSigningSecretKey.length !== 32
        ) {
            throw new Error("Invalid MLS epoch configuration");
        }
        const localMember = options.members[options.localLeaf];
        if (
            localMember === undefined ||
            localMember.signatureKey.length !== 32 ||
            options.members.some(
                (member) =>
                    member !== undefined &&
                    (member.signatureKey.length !== 32 ||
                        (member.encryptionKey !== undefined && member.encryptionKey.length !== 32)),
            )
        ) {
            throw new Error("Invalid MLS epoch member");
        }
        const ownershipSignature = mlsSignWithLabel(
            options.localSigningSecretKey,
            OWNERSHIP_LABEL,
            OWNERSHIP_CONTENT,
        );
        if (
            !mlsVerifyWithLabel(
                localMember.signatureKey,
                OWNERSHIP_LABEL,
                OWNERSHIP_CONTENT,
                ownershipSignature,
            )
        ) {
            throw new Error("MLS local signing key does not match its leaf");
        }
        if (
            epochSecretValues(inputSecrets).some(
                (secret) => !(secret instanceof Uint8Array) || secret.length !== 32,
            )
        ) {
            throw new Error("Invalid MLS epoch secrets");
        }

        const ownedSecrets = copyEpochSecrets(inputSecrets);
        let localSigningSecretKey: Uint8Array | undefined;
        let secretTree: MlsSecretTree | undefined;
        try {
            localSigningSecretKey = options.localSigningSecretKey.slice();
            const members = options.members.map((member) =>
                member === undefined
                    ? undefined
                    : member.encryptionKey === undefined
                      ? { signatureKey: member.signatureKey.slice() }
                      : {
                            signatureKey: member.signatureKey.slice(),
                            encryptionKey: member.encryptionKey.slice(),
                        },
            );
            if (
                options.interimTranscriptHash !== undefined &&
                options.interimTranscriptHash.length !== 32
            ) {
                throw new Error("Invalid MLS interim transcript hash");
            }
            secretTree = new MlsSecretTree(ownedSecrets.encryptionSecret, members.length);
            this.#context = copyContext(options.context);
            this.#secrets = ownedSecrets;
            this.#members = members;
            this.#localLeaf = options.localLeaf;
            this.#localSigningSecretKey = localSigningSecretKey;
            this.#secretTree = secretTree;
            this.#interimTranscriptHash = options.interimTranscriptHash?.slice();
        } catch (error: unknown) {
            secretTree?.destroy();
            destroyMlsEpochSecrets(ownedSecrets);
            if (localSigningSecretKey !== undefined) {
                zeroBytes(localSigningSecretKey);
            }
            throw error;
        }
        destroyMlsEpochSecrets(inputSecrets);
    }

    /** Immutable public context for this epoch. */
    get context(): MlsGroupContext {
        this.#ensureActive();
        return copyContext(this.#context);
    }

    /** Sign and encrypt application bytes as the local member. */
    seal(
        applicationData: Uint8Array,
        authenticatedData: Uint8Array = new Uint8Array(),
        paddingBytes: number = 0,
    ): Uint8Array {
        this.#ensureActive();
        if (this.#transitionState !== "idle") {
            throw new Error("MLS epoch has a pending transition");
        }
        return sealMlsApplicationMessage({
            context: this.#context,
            sender: this.#localLeaf,
            signingSecretKey: this.#localSigningSecretKey,
            senderDataSecret: this.#secrets.senderDataSecret,
            secretTree: this.#secretTree,
            applicationData,
            authenticatedData,
            paddingBytes,
        });
    }

    /** Authenticate and decrypt application bytes from another member. */
    open(message: Uint8Array): OpenedMlsApplicationMessage {
        this.#ensureActive();
        return openMlsApplicationMessage({
            context: this.#context,
            senderDataSecret: this.#secrets.senderDataSecret,
            secretTree: this.#secretTree,
            message,
            signatureKeyFor: (sender) => this.#members[sender]?.signatureKey,
        });
    }

    /**
     * Prepare an authenticated add-only Commit, Welcome, and next epoch.
     *
     * The current epoch stays active until the caller durably publishes the
     * Commit. The caller then destroys it and adopts the returned epoch.
     */
    prepareAdd(
        additions: readonly MlsKeyPackage[],
        validateExternalTree: MlsAddTreeValidator,
        authenticatedData: Uint8Array = new Uint8Array(),
    ): PreparedMlsAddEpoch {
        this.#ensureActive();
        const interimTranscriptHash = this.#requireInterimTranscriptHash();
        const members = this.#commitMembers();
        this.#beginTransitionPreparation();
        let tree: MlsExternalTreeTransition | undefined;
        let created: ReturnType<typeof createMlsAddCommit>;
        try {
            created = createMlsAddCommit({
                context: this.#context,
                interimTranscriptHash,
                nextInitSecret: this.#secrets.nextInitSecret,
                membershipKey: this.#secrets.membershipKey,
                members,
                sender: this.#localLeaf,
                signingSecretKey: this.#localSigningSecretKey,
                additions,
                validateExternalTree: (nextAdditions, nextMembers) => {
                    if (tree !== undefined) {
                        throw new Error("MLS external tree validator ran more than once");
                    }
                    tree = validateExternalTree(nextAdditions, nextMembers);
                    return tree.treeHash;
                },
                authenticatedData,
            });
        } catch (error: unknown) {
            try {
                tree?.cancel();
            } finally {
                this.#abortTransitionPreparation();
            }
            throw error;
        }
        if (tree === undefined) {
            this.#abortTransitionPreparation();
            destroyMlsEpochSecrets(created.secrets);
            throw new Error("MLS external tree validator did not return a transition");
        }
        let next: MlsEpochState | undefined;
        try {
            next = new MlsEpochState({
                context: created.context,
                secrets: created.secrets,
                members: created.members,
                localLeaf: this.#localLeaf,
                localSigningSecretKey: this.#localSigningSecretKey,
                interimTranscriptHash: created.interimTranscriptHash,
            });
            return {
                commit: created.commit,
                welcome: created.welcome,
                transition: this.#stage(next, tree),
            };
        } catch (error: unknown) {
            try {
                tree.cancel();
            } finally {
                try {
                    next?.destroy();
                    destroyMlsEpochSecrets(created.secrets);
                } finally {
                    this.#abortTransitionPreparation();
                }
            }
            throw error;
        }
    }

    /**
     * Authenticate an add-only Commit and construct the next local epoch.
     *
     * External tree validation must be side-effect-free until this succeeds.
     */
    applyAdd(message: Uint8Array, validateExternalTree: MlsAddTreeValidator): MlsEpochTransition {
        this.#ensureActive();
        this.#beginTransitionPreparation();
        let tree: MlsExternalTreeTransition | undefined;
        let applied: ReturnType<typeof openMlsAddCommit>;
        try {
            applied = openMlsAddCommit({
                message,
                context: this.#context,
                interimTranscriptHash: this.#requireInterimTranscriptHash(),
                nextInitSecret: this.#secrets.nextInitSecret,
                membershipKey: this.#secrets.membershipKey,
                members: this.#commitMembers(),
                validateExternalTree: (additions, nextMembers) => {
                    if (tree !== undefined) {
                        throw new Error("MLS external tree validator ran more than once");
                    }
                    tree = validateExternalTree(additions, nextMembers);
                    return tree.treeHash;
                },
            });
        } catch (error: unknown) {
            try {
                tree?.cancel();
            } finally {
                this.#abortTransitionPreparation();
            }
            throw error;
        }
        if (tree === undefined) {
            this.#abortTransitionPreparation();
            destroyMlsEpochSecrets(applied.secrets);
            throw new Error("MLS external tree validator did not return a transition");
        }
        let next: MlsEpochState | undefined;
        try {
            next = new MlsEpochState({
                context: applied.context,
                secrets: applied.secrets,
                members: applied.members,
                localLeaf: this.#localLeaf,
                localSigningSecretKey: this.#localSigningSecretKey,
                interimTranscriptHash: applied.interimTranscriptHash,
            });
            return this.#stage(next, tree);
        } catch (error: unknown) {
            try {
                tree.cancel();
            } finally {
                try {
                    next?.destroy();
                    destroyMlsEpochSecrets(applied.secrets);
                } finally {
                    this.#abortTransitionPreparation();
                }
            }
            throw error;
        }
    }

    /** Destroy the epoch and every secret it owns. */
    destroy(): void {
        if (this.#destroyed) {
            return;
        }
        try {
            this.#pendingTransition?.cancel();
        } finally {
            this.#destroyed = true;
            this.#secretTree.destroy();
            destroyMlsEpochSecrets(this.#secrets);
            zeroBytes(this.#localSigningSecretKey);
            if (this.#interimTranscriptHash !== undefined) {
                zeroBytes(this.#interimTranscriptHash);
            }
        }
    }

    #ensureActive(): void {
        if (this.#destroyed) {
            throw new Error("MLS epoch was destroyed");
        }
    }

    #beginTransitionPreparation(): void {
        if (this.#transitionState !== "idle") {
            throw new Error("MLS epoch already has a pending transition");
        }
        this.#transitionState = "preparing";
    }

    #abortTransitionPreparation(): void {
        if (this.#transitionState === "preparing") {
            this.#transitionState = "idle";
        }
    }

    #stage(next: MlsEpochState, tree: MlsExternalTreeTransition): StagedEpochTransition {
        if (this.#transitionState !== "preparing") {
            next.destroy();
            throw new Error("MLS epoch transition was not reserved");
        }
        const transition = new StagedEpochTransition(this, next, tree, () => {
            this.#pendingTransition = undefined;
            this.#transitionState = "idle";
        });
        this.#pendingTransition = transition;
        this.#transitionState = "staged";
        return transition;
    }

    #requireInterimTranscriptHash(): Uint8Array {
        if (this.#interimTranscriptHash === undefined) {
            throw new Error("MLS epoch has no interim transcript hash");
        }
        return this.#interimTranscriptHash;
    }

    #commitMembers(): readonly (MlsCommitMember | undefined)[] {
        return this.#members.map((member) => {
            if (member === undefined) {
                return undefined;
            }
            if (member.encryptionKey === undefined) {
                throw new Error("MLS epoch member is missing its leaf encryption key");
            }
            return {
                signatureKey: member.signatureKey,
                encryptionKey: member.encryptionKey,
            };
        });
    }
}

/** Adopt an authenticated Welcome while deriving its interim transcript hash. */
export function createMlsEpochFromWelcome(
    options: CreateMlsEpochFromWelcomeOptions,
): MlsEpochState {
    if (!equalBytes(options.tree.treeHash, options.opened.groupInfo.context.treeHash)) {
        throw new Error("MLS Welcome tree view does not match GroupInfo");
    }
    return new MlsEpochState({
        context: options.opened.groupInfo.context,
        secrets: options.opened.epochSecrets,
        members: options.tree.members,
        localLeaf: options.tree.localLeaf,
        localSigningSecretKey: options.localSigningSecretKey,
        interimTranscriptHash: updateInterimTranscriptHash(
            options.opened.groupInfo.context.confirmedTranscriptHash,
            options.opened.groupInfo.confirmationTag,
        ),
    });
}
