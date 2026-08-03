import { equalBytes, hashBytes, zeroBytes } from "@slopus/murmur";
import {
    canonicalizeHpkePublicKey,
    isHpkeKeyPair,
    mlsDeriveSecret,
    mlsExpandWithLabel,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import {
    createMlsAddCommit,
    createMlsTreeCommit,
    destroyMlsTreeCommitResult,
    openMlsAddCommit,
    openMlsTreeCommit,
    type MlsCommitMember,
} from "../commit/index.js";
import {
    encodeMlsGroupContext,
    updateInterimTranscriptHash,
    type MlsGroupContext,
} from "../groupContext/index.js";
import type { MlsKeyPackage } from "../keyPackage/index.js";
import { destroyMlsEpochSecrets, type MlsEpochSecrets } from "../keySchedule/index.js";
import { decodeMlsLeafNodeBytes, type MlsLeafNode } from "../leafNode/index.js";
import {
    openMlsApplicationMessage,
    sealMlsApplicationMessage,
    type OpenedMlsApplicationMessage,
} from "../privateMessage/index.js";
import { type MlsRatchetTree } from "../ratchetTree/index.js";
import { destroyMlsSecretTreeState, MlsSecretTree } from "../secretTree/index.js";
import { directPath, leafNode } from "../tree/index.js";
import {
    deriveMlsWelcomePrivateKeys,
    destroyMlsTreePrivateKeys,
    type MlsTreePrivateKey,
} from "../updatePath/index.js";
import {
    decodeMlsEpochState,
    destroyDecodedMlsEpochState,
    encodeMlsEpochState,
} from "./impl/stateCodec.js";
import type {
    CreateLegacyMlsEpochOptions,
    CreateMlsEpochOptions,
    CreateMlsEpochFromWelcomeOptions,
    CreateMlsTreeEpochFromWelcomeOptions,
    CreateTreeMlsEpochOptions,
    DeserializeMlsEpochOptions,
    MlsAddTreeValidator,
    MlsEpochCommitProposal,
    MlsEpochMember,
    MlsEpochTransition,
    MlsExternalTreeTransition,
    PreparedMlsAddEpoch,
    PreparedMlsTreeEpoch,
} from "./types.js";

export type {
    CreateLegacyMlsEpochOptions,
    CreateMlsEpochOptions,
    CreateMlsEpochFromWelcomeOptions,
    CreateMlsTreeEpochFromWelcomeOptions,
    CreateTreeMlsEpochOptions,
    DeserializeMlsEpochOptions,
    MlsAddTreeValidator,
    MlsEpochCommitProposal,
    MlsEpochMember,
    MlsEpochTransition,
    MlsExternalTreeTransition,
    PreparedMlsAddEpoch,
    PreparedMlsTreeEpoch,
    MlsValidatedWelcomeTree,
} from "./types.js";

const OWNERSHIP_LABEL = "Murmur Epoch Ownership";
const OWNERSHIP_CONTENT = new Uint8Array();
const MAXIMUM_EPOCH_MEMBERS = 100_000;
const MAXIMUM_PERSISTENCE_GENERATION = 0xffff_ffff_ffff_ffffn;

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

function membersFromTree(tree: MlsRatchetTree): readonly (MlsEpochMember | undefined)[] {
    const nodes = tree.nodes;
    return Array.from({ length: tree.leafCount }, (_, leaf) => {
        const node = nodes[leafNode(leaf, tree.leafCount)];
        if (node?.type !== "leaf") {
            return undefined;
        }
        const decoded = decodeMlsLeafNodeBytes(node.encoded);
        return {
            signatureKey: decoded.signatureKey.slice(),
            encryptionKey: decoded.encryptionKey.slice(),
        };
    });
}

function copyAndValidateTreePrivateKeys(
    tree: MlsRatchetTree,
    localLeaf: number,
    privateKeys: readonly MlsTreePrivateKey[],
): readonly MlsTreePrivateKey[] {
    const allowed = new Set([
        leafNode(localLeaf, tree.leafCount),
        ...directPath(localLeaf, tree.leafCount),
    ]);
    const nodes = tree.nodes;
    const seen = new Set<number>();
    const copies: MlsTreePrivateKey[] = [];
    try {
        for (const key of privateKeys) {
            const node = nodes[key.node];
            if (
                !Number.isSafeInteger(key.node) ||
                !allowed.has(key.node) ||
                seen.has(key.node) ||
                node === undefined ||
                !isHpkeKeyPair(key.keyPair) ||
                !equalBytes(
                    canonicalizeHpkePublicKey(node.encryptionKey),
                    canonicalizeHpkePublicKey(key.keyPair.publicKey),
                )
            ) {
                throw new Error("Invalid MLS epoch TreeKEM private key");
            }
            seen.add(key.node);
            copies.push({
                node: key.node,
                keyPair: {
                    secretKey: key.keyPair.secretKey.slice(),
                    publicKey: node.encryptionKey.slice(),
                },
            });
        }
        if (!seen.has(leafNode(localLeaf, tree.leafCount))) {
            throw new Error("MLS epoch is missing its leaf private key");
        }
        for (const nodeIndex of directPath(localLeaf, tree.leafCount)) {
            const node = nodes[nodeIndex];
            if (
                node?.type === "parent" &&
                !node.unmergedLeaves.includes(localLeaf) &&
                !seen.has(nodeIndex)
            ) {
                throw new Error("MLS epoch is missing a merged direct-path private key");
            }
        }
        return copies;
    } catch (error: unknown) {
        destroyMlsTreePrivateKeys(copies);
        throw error;
    }
}

class StagedEpochTransition implements MlsEpochTransition {
    readonly #current: MlsEpochState;
    readonly #next: MlsEpochState;
    readonly #external: MlsExternalTreeTransition | undefined;
    readonly #onSettle: () => void;
    readonly sender: number;
    #state: "pending" | "committing" | "cancelling" | "settled" = "pending";

    constructor(
        current: MlsEpochState,
        next: MlsEpochState,
        external: MlsExternalTreeTransition | undefined,
        sender: number,
        onSettle: () => void,
    ) {
        this.#current = current;
        this.#next = next;
        this.#external = external;
        this.sender = sender;
        this.#onSettle = onSettle;
    }

    /** Monotonic generation of the staged next-epoch checkpoint. */
    get persistenceGeneration(): bigint {
        this.#ensurePending();
        return this.#next.persistenceGeneration;
    }

    /** Serialize the staged next epoch for atomic Commit/outbox persistence. */
    serialize(): Uint8Array {
        this.#ensurePending();
        return this.#next.serialize();
    }

    commit(): MlsEpochState {
        this.#ensurePending();
        this.#state = "committing";
        try {
            this.#external?.commit();
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
            this.#external?.cancel();
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
 * `options.secrets` and integrated TreeKEM private keys by cloning them
 * privately and zeroing every input array. A restored Secret Tree snapshot is
 * likewise copied and consumed only after successful construction.
 * Construction failure leaves ownership with the caller. Full Commit
 * transitions stage an independently owned next state until explicit adoption
 * or cancellation.
 */
export class MlsEpochState {
    readonly #context: MlsGroupContext;
    readonly #secrets: MlsEpochSecrets;
    readonly #members: readonly (MlsEpochMember | undefined)[];
    readonly #localLeaf: number;
    readonly #localSigningSecretKey: Uint8Array;
    #secretTree: MlsSecretTree;
    readonly #interimTranscriptHash: Uint8Array | undefined;
    readonly #tree: MlsRatchetTree | undefined;
    readonly #privateKeys: readonly MlsTreePrivateKey[];
    readonly #authenticateCredential:
        | ((leafNode: MlsLeafNode, leafIndex: number) => boolean)
        | undefined;
    #persistenceGeneration: bigint;
    #destroyed = false;
    #pendingTransition: StagedEpochTransition | undefined;
    #transitionState: "idle" | "preparing" | "staged" = "idle";

    constructor(options: CreateMlsEpochOptions) {
        encodeMlsGroupContext(options.context);
        if (
            (options.context.epoch === 0n) !==
            (options.context.confirmedTranscriptHash.length === 0)
        ) {
            throw new Error("Invalid final MLS epoch transcript");
        }
        const inputSecrets = snapshotEpochSecrets(options.secrets);
        const integrated =
            options.tree === undefined ? undefined : (options as CreateTreeMlsEpochOptions);
        let tree: MlsRatchetTree | undefined;
        let configuredMembers: readonly (MlsEpochMember | undefined)[];
        if (integrated === undefined) {
            configuredMembers = (options as CreateLegacyMlsEpochOptions).members;
        } else {
            tree = integrated.tree.clone();
            tree.validate({
                groupId: options.context.groupId,
                authenticateCredential: integrated.authenticateCredential,
            });
            if (!equalBytes(tree.treeHash(), options.context.treeHash)) {
                throw new Error("MLS epoch tree does not match its GroupContext");
            }
            configuredMembers = membersFromTree(tree);
        }
        if (
            configuredMembers.length === 0 ||
            configuredMembers.length > MAXIMUM_EPOCH_MEMBERS ||
            !Number.isSafeInteger(options.localLeaf) ||
            options.localLeaf < 0 ||
            options.localLeaf >= configuredMembers.length ||
            options.localSigningSecretKey.length !== 32 ||
            (options.persistenceGeneration !== undefined &&
                (options.persistenceGeneration < 0n ||
                    options.persistenceGeneration > MAXIMUM_PERSISTENCE_GENERATION))
        ) {
            throw new Error("Invalid MLS epoch configuration");
        }
        const localMember = configuredMembers[options.localLeaf];
        if (
            localMember === undefined ||
            localMember.signatureKey.length !== 32 ||
            configuredMembers.some(
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
        let privateKeys: readonly MlsTreePrivateKey[] = [];
        try {
            localSigningSecretKey = options.localSigningSecretKey.slice();
            const members = configuredMembers.map((member) =>
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
            if (integrated !== undefined && tree !== undefined) {
                privateKeys = copyAndValidateTreePrivateKeys(
                    tree,
                    options.localLeaf,
                    integrated.privateKeys,
                );
            }
            if (
                options.secretTreeState !== undefined &&
                options.secretTreeState.leafCount !== members.length
            ) {
                throw new Error("MLS Secret Tree snapshot does not match epoch members");
            }
            secretTree =
                options.secretTreeState === undefined
                    ? new MlsSecretTree(ownedSecrets.encryptionSecret, members.length)
                    : MlsSecretTree.fromState(options.secretTreeState);
            zeroBytes(ownedSecrets.joinerSecret);
            zeroBytes(ownedSecrets.memberSecret);
            zeroBytes(ownedSecrets.epochSecret);
            zeroBytes(ownedSecrets.encryptionSecret);
            this.#context = copyContext(options.context);
            this.#secrets = ownedSecrets;
            this.#members = members;
            this.#localLeaf = options.localLeaf;
            this.#localSigningSecretKey = localSigningSecretKey;
            this.#secretTree = secretTree;
            this.#interimTranscriptHash = options.interimTranscriptHash?.slice();
            this.#tree = tree;
            this.#privateKeys = privateKeys;
            this.#authenticateCredential = integrated?.authenticateCredential;
            this.#persistenceGeneration = options.persistenceGeneration ?? 0n;
        } catch (error: unknown) {
            secretTree?.destroy();
            destroyMlsTreePrivateKeys(privateKeys);
            destroyMlsEpochSecrets(ownedSecrets);
            if (localSigningSecretKey !== undefined) {
                zeroBytes(localSigningSecretKey);
            }
            throw error;
        }
        destroyMlsEpochSecrets(inputSecrets);
        if (integrated !== undefined) {
            destroyMlsTreePrivateKeys(integrated.privateKeys);
        }
        if (options.secretTreeState !== undefined) {
            destroyMlsSecretTreeState(options.secretTreeState);
        }
    }

    /**
     * Restore an authenticated local epoch without persisting its signing key.
     *
     * Integrated TreeKEM records require the same credential authenticator used
     * for external tree validation. The supplied signing key is rebound to the
     * authenticated local LeafNode by the constructor.
     */
    static deserialize(bytes: Uint8Array, options: DeserializeMlsEpochOptions): MlsEpochState {
        const decoded = decodeMlsEpochState(bytes, options.authenticateCredential);
        try {
            if (
                options.minimumPersistenceGeneration < 0n ||
                options.minimumPersistenceGeneration > MAXIMUM_PERSISTENCE_GENERATION ||
                decoded.persistenceGeneration < options.minimumPersistenceGeneration
            ) {
                throw new Error("Durable MLS epoch state was rolled back");
            }
            if (decoded.tree === undefined) {
                if (decoded.members === undefined) {
                    throw new Error("Durable legacy MLS epoch is missing members");
                }
                return new MlsEpochState({
                    context: decoded.context,
                    secrets: decoded.secrets,
                    members: decoded.members,
                    localLeaf: decoded.localLeaf,
                    localSigningSecretKey: options.localSigningSecretKey,
                    persistenceGeneration: decoded.persistenceGeneration,
                    ...(decoded.interimTranscriptHash === undefined
                        ? {}
                        : { interimTranscriptHash: decoded.interimTranscriptHash }),
                    secretTreeState: decoded.secretTreeState,
                });
            }
            if (options.authenticateCredential === undefined) {
                throw new Error("Durable TreeKEM state requires credential authentication");
            }
            return new MlsEpochState({
                context: decoded.context,
                secrets: decoded.secrets,
                tree: decoded.tree,
                privateKeys: decoded.privateKeys,
                localLeaf: decoded.localLeaf,
                localSigningSecretKey: options.localSigningSecretKey,
                authenticateCredential: options.authenticateCredential,
                persistenceGeneration: decoded.persistenceGeneration,
                ...(decoded.interimTranscriptHash === undefined
                    ? {}
                    : { interimTranscriptHash: decoded.interimTranscriptHash }),
                secretTreeState: decoded.secretTreeState,
            });
        } finally {
            destroyDecodedMlsEpochState(decoded);
        }
    }

    /** Immutable public context for this epoch. */
    get context(): MlsGroupContext {
        this.#ensureActive();
        return copyContext(this.#context);
    }

    /** Monotonic generation to store with the durable epoch checkpoint. */
    get persistenceGeneration(): bigint {
        this.#ensureActive();
        return this.#persistenceGeneration;
    }

    /** Defensive copy of the stable MLS group identifier. */
    get groupId(): Uint8Array {
        this.#ensureActive();
        return this.#context.groupId.slice();
    }

    /** Defensive member signing-key view indexed by MLS leaf number. */
    get memberSignatureKeys(): readonly (Uint8Array | undefined)[] {
        this.#ensureActive();
        return this.#members.map((member) => member?.signatureKey.slice());
    }

    /** MLS leaf index of the local member inside this epoch. */
    get localLeaf(): number {
        this.#ensureActive();
        return this.#localLeaf;
    }

    /**
     * RFC 9420 section 8.5 MLS-Exporter for this epoch.
     *
     * Exported material keys an application-defined protocol from the epoch's
     * exporter secret. It deliberately reads no Secret Tree ratchet and does
     * not advance the persistence generation, so an exporter user needs no
     * durable checkpoint and can be entirely ephemeral. Every epoch produces
     * unrelated material, which is what makes a membership Commit an effective
     * revocation for exporter-keyed traffic as well.
     */
    exportSecret(label: string, context: Uint8Array, length: number): Uint8Array {
        this.#ensureActive();
        if (this.#transitionState !== "idle") {
            throw new Error("MLS epoch has a pending transition");
        }
        const derived = mlsDeriveSecret(this.#secrets.exporterSecret, label);
        try {
            return mlsExpandWithLabel(derived, "exported", hashBytes(context), length);
        } finally {
            zeroBytes(derived);
        }
    }

    /**
     * Serialize this active epoch's sensitive local state.
     *
     * The returned bytes do not contain the local signing secret key. They must
     * nevertheless be stored confidentially because they contain epoch,
     * TreeKEM, and sender-ratchet secrets.
     */
    serialize(): Uint8Array {
        this.#ensureActive();
        if (this.#transitionState !== "idle") {
            throw new Error("Cannot serialize an MLS epoch with a pending transition");
        }
        const secretTreeState = this.#secretTree.snapshot();
        try {
            return encodeMlsEpochState({
                context: this.#context,
                secrets: this.#secrets,
                ...(this.#tree === undefined ? { members: this.#members } : { tree: this.#tree }),
                privateKeys: this.#privateKeys,
                localLeaf: this.#localLeaf,
                persistenceGeneration: this.#persistenceGeneration,
                ...(this.#interimTranscriptHash === undefined
                    ? {}
                    : { interimTranscriptHash: this.#interimTranscriptHash }),
                secretTreeState,
            });
        } finally {
            destroyMlsSecretTreeState(secretTreeState);
        }
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
        this.#persistenceGeneration = this.#nextPersistenceGeneration();
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
        if (this.#transitionState !== "idle") {
            throw new Error("MLS epoch has a pending transition");
        }
        this.#persistenceGeneration = this.#nextPersistenceGeneration();
        return openMlsApplicationMessage({
            context: this.#context,
            senderDataSecret: this.#secrets.senderDataSecret,
            secretTree: this.#secretTree,
            message,
            signatureKeyFor: (sender) => this.#members[sender]?.signatureKey,
        });
    }

    /**
     * Authenticate an application message and create its durable checkpoint as
     * one rollback-safe operation.
     *
     * If either authentication or checkpoint serialization fails, the prior
     * Secret Tree and persistence generation are restored before the error is
     * rethrown.
     */
    openWithCheckpoint(message: Uint8Array): {
        readonly message: OpenedMlsApplicationMessage;
        readonly state: Uint8Array;
        readonly persistenceGeneration: bigint;
    } {
        this.#ensureActive();
        if (this.#transitionState !== "idle") {
            throw new Error("MLS epoch has a pending transition");
        }
        const priorTree = this.#secretTree.snapshot();
        const priorGeneration = this.#persistenceGeneration;
        let opened: OpenedMlsApplicationMessage | undefined;
        try {
            opened = this.open(message);
            return {
                message: opened,
                state: this.serialize(),
                persistenceGeneration: this.#persistenceGeneration,
            };
        } catch (error: unknown) {
            if (opened !== undefined) {
                zeroBytes(opened.applicationData);
                zeroBytes(opened.authenticatedData);
            }
            let restored: MlsSecretTree;
            try {
                restored = MlsSecretTree.fromState(priorTree);
            } catch (rollbackError: unknown) {
                throw new Error("MLS epoch checkpoint rollback failed", {
                    cause: rollbackError,
                });
            }
            this.#secretTree.destroy();
            this.#secretTree = restored;
            this.#persistenceGeneration = priorGeneration;
            throw error;
        } finally {
            destroyMlsSecretTreeState(priorTree);
        }
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
        this.#ensureLegacyTransitionMode();
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
                persistenceGeneration: this.#nextPersistenceGeneration(),
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
        this.#ensureLegacyTransitionMode();
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
                persistenceGeneration: this.#nextPersistenceGeneration(),
            });
            return this.#stage(next, tree, applied.message.sender);
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

    /**
     * Prepare a full Add/Remove Commit and an integrated next TreeKEM epoch.
     *
     * The transition blocks current-epoch sends until `commit()` adopts the
     * next epoch or `cancel()` destroys the staged secrets.
     */
    prepareCommit(
        proposals: readonly MlsEpochCommitProposal[],
        authenticatedData: Uint8Array = new Uint8Array(),
    ): PreparedMlsTreeEpoch {
        this.#ensureActive();
        const interimTranscriptHash = this.#requireInterimTranscriptHash();
        const tree = this.#requireIntegratedTree();
        const authenticateCredential = this.#requireCredentialAuthenticator();
        this.#beginTransitionPreparation();
        let created: ReturnType<typeof createMlsTreeCommit> | undefined;
        let next: MlsEpochState | undefined;
        try {
            created = createMlsTreeCommit({
                context: this.#context,
                interimTranscriptHash,
                nextInitSecret: this.#secrets.nextInitSecret,
                membershipKey: this.#secrets.membershipKey,
                tree,
                sender: this.#localLeaf,
                signingSecretKey: this.#localSigningSecretKey,
                proposals,
                authenticateCredential,
                authenticatedData,
            });
            next = new MlsEpochState({
                context: created.context,
                secrets: created.secrets,
                tree: created.tree,
                privateKeys: created.privateKeys,
                localLeaf: this.#localLeaf,
                localSigningSecretKey: this.#localSigningSecretKey,
                authenticateCredential,
                interimTranscriptHash: created.interimTranscriptHash,
                persistenceGeneration: this.#nextPersistenceGeneration(),
            });
            return {
                commit: created.commit,
                ...(created.welcome === undefined ? {} : { welcome: created.welcome }),
                tree: created.tree.clone(),
                addedLeaves: [...created.addedLeaves],
                removedLeaves: [...created.removedLeaves],
                transition: this.#stage(next),
            };
        } catch (error: unknown) {
            next?.destroy();
            this.#abortTransitionPreparation();
            throw error;
        } finally {
            if (created !== undefined) {
                destroyMlsTreeCommitResult(created);
            }
        }
    }

    /** Authenticate a full Add/Remove Commit and stage the retained next epoch. */
    applyCommit(message: Uint8Array): MlsEpochTransition {
        this.#ensureActive();
        const interimTranscriptHash = this.#requireInterimTranscriptHash();
        const tree = this.#requireIntegratedTree();
        const authenticateCredential = this.#requireCredentialAuthenticator();
        this.#beginTransitionPreparation();
        let applied: ReturnType<typeof openMlsTreeCommit> | undefined;
        let next: MlsEpochState | undefined;
        try {
            applied = openMlsTreeCommit({
                message,
                context: this.#context,
                interimTranscriptHash,
                nextInitSecret: this.#secrets.nextInitSecret,
                membershipKey: this.#secrets.membershipKey,
                tree,
                localLeaf: this.#localLeaf,
                privateKeys: this.#privateKeys,
                authenticateCredential,
            });
            next = new MlsEpochState({
                context: applied.context,
                secrets: applied.secrets,
                tree: applied.tree,
                privateKeys: applied.privateKeys,
                localLeaf: this.#localLeaf,
                localSigningSecretKey: this.#localSigningSecretKey,
                authenticateCredential,
                interimTranscriptHash: applied.interimTranscriptHash,
                persistenceGeneration: this.#nextPersistenceGeneration(),
            });
            return this.#stage(next, undefined, applied.message.sender);
        } catch (error: unknown) {
            next?.destroy();
            this.#abortTransitionPreparation();
            throw error;
        } finally {
            if (applied !== undefined) {
                destroyMlsTreeCommitResult(applied);
            }
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
            destroyMlsTreePrivateKeys(this.#privateKeys);
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

    #nextPersistenceGeneration(): bigint {
        if (this.#persistenceGeneration >= MAXIMUM_PERSISTENCE_GENERATION) {
            throw new Error("MLS persistence generation is exhausted");
        }
        return this.#persistenceGeneration + 1n;
    }

    #abortTransitionPreparation(): void {
        if (this.#transitionState === "preparing") {
            this.#transitionState = "idle";
        }
    }

    #stage(
        next: MlsEpochState,
        external?: MlsExternalTreeTransition,
        sender: number = this.#localLeaf,
    ): StagedEpochTransition {
        if (this.#transitionState !== "preparing") {
            next.destroy();
            throw new Error("MLS epoch transition was not reserved");
        }
        const transition = new StagedEpochTransition(this, next, external, sender, () => {
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

    #requireIntegratedTree(): MlsRatchetTree {
        if (this.#tree === undefined) {
            throw new Error("MLS epoch has no integrated TreeKEM state");
        }
        return this.#tree;
    }

    #requireCredentialAuthenticator(): (leafNode: MlsLeafNode, leafIndex: number) => boolean {
        if (this.#authenticateCredential === undefined) {
            throw new Error("MLS epoch has no credential authenticator");
        }
        return this.#authenticateCredential;
    }

    #ensureLegacyTransitionMode(): void {
        if (this.#tree !== undefined) {
            throw new Error("Integrated TreeKEM epochs must use full Commit transitions");
        }
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
    if (options.opened.pathSecret !== undefined) {
        throw new Error("Path-bearing MLS Welcome requires integrated TreeKEM adoption");
    }
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

/**
 * Adopt an authenticated Welcome into an epoch which owns full TreeKEM state.
 *
 * On success this consumes the opened epoch secrets, the supplied leaf private
 * key, and the optional Welcome path secret.
 */
export function createMlsTreeEpochFromWelcome(
    options: CreateMlsTreeEpochFromWelcomeOptions,
): MlsEpochState {
    if (!equalBytes(options.tree.treeHash(), options.opened.groupInfo.context.treeHash)) {
        throw new Error("MLS Welcome tree does not match GroupInfo");
    }
    const privateKeys = deriveMlsWelcomePrivateKeys({
        tree: options.tree,
        groupId: options.opened.groupInfo.context.groupId,
        sender: options.opened.groupInfo.signer,
        localLeaf: options.localLeaf,
        leafKeyPair: options.leafKeyPair,
        ...(options.opened.pathSecret === undefined
            ? {}
            : { pathSecret: options.opened.pathSecret }),
        authenticateCredential: options.authenticateCredential,
    });
    try {
        const epoch = new MlsEpochState({
            context: options.opened.groupInfo.context,
            secrets: options.opened.epochSecrets,
            tree: options.tree,
            privateKeys,
            localLeaf: options.localLeaf,
            localSigningSecretKey: options.localSigningSecretKey,
            authenticateCredential: options.authenticateCredential,
            interimTranscriptHash: updateInterimTranscriptHash(
                options.opened.groupInfo.context.confirmedTranscriptHash,
                options.opened.groupInfo.confirmationTag,
            ),
        });
        if (options.opened.pathSecret !== undefined) {
            zeroBytes(options.opened.pathSecret);
        }
        zeroBytes(options.leafKeyPair.secretKey);
        return epoch;
    } finally {
        destroyMlsTreePrivateKeys(privateKeys);
    }
}
