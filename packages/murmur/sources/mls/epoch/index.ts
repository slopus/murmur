import { equalBytes, hashBytes, zeroBytes } from "../internal.js";
import {
    canonicalizeHpkePublicKey,
    isHpkeKeyPair,
    mlsDeriveSecret,
    mlsExpandWithLabel,
    mlsSignWithLabel,
    mlsVerifyWithLabel,
} from "../cipherSuite/index.js";
import {
    createMlsTreeCommit,
    destroyMlsTreeCommitResult,
    openMlsTreeCommit,
} from "../commit/index.js";
import {
    encodeMlsGroupContext,
    updateInterimTranscriptHash,
    type MlsGroupContext,
} from "../groupContext/index.js";
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
    CreateMlsEpochOptions,
    CreateMlsTreeEpochFromWelcomeOptions,
    DeserializeMlsEpochOptions,
    MlsEpochCommitProposal,
    MlsEpochMember,
    MlsEpochTransition,
    PreparedMlsTreeEpoch,
} from "./types.js";

export type {
    CreateMlsEpochOptions,
    CreateMlsTreeEpochFromWelcomeOptions,
    DeserializeMlsEpochOptions,
    MlsEpochCommitProposal,
    MlsEpochMember,
    MlsEpochTransition,
    PreparedMlsTreeEpoch,
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
    readonly #onSettle: () => void;
    readonly sender: number;
    #state: "pending" | "committing" | "cancelling" | "settled" = "pending";

    constructor(current: MlsEpochState, next: MlsEpochState, sender: number, onSettle: () => void) {
        this.#current = current;
        this.#next = next;
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
        this.#state = "settled";
        this.#onSettle();
        this.#current.destroy();
        return this.#next;
    }

    cancel(): void {
        this.#ensurePending();
        this.#state = "cancelling";
        try {
            this.#next.destroy();
        } finally {
            this.#state = "settled";
            this.#onSettle();
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
    readonly #tree: MlsRatchetTree;
    readonly #privateKeys: readonly MlsTreePrivateKey[];
    readonly #authenticateCredential: (leafNode: MlsLeafNode, leafIndex: number) => boolean;
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
        const tree = options.tree.clone();
        tree.validate({
            groupId: options.context.groupId,
            authenticateCredential: options.authenticateCredential,
        });
        if (!equalBytes(tree.treeHash(), options.context.treeHash)) {
            throw new Error("MLS epoch tree does not match its GroupContext");
        }
        const configuredMembers = membersFromTree(tree);
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
            privateKeys = copyAndValidateTreePrivateKeys(
                tree,
                options.localLeaf,
                options.privateKeys,
            );
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
            this.#authenticateCredential = options.authenticateCredential;
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
        destroyMlsTreePrivateKeys(options.privateKeys);
        if (options.secretTreeState !== undefined) {
            destroyMlsSecretTreeState(options.secretTreeState);
        }
    }

    /**
     * Restore an authenticated local epoch without persisting its signing key.
     *
     * TreeKEM records require the same credential authenticator used for tree
     * validation. The supplied signing key is rebound to the
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
                tree: this.#tree,
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

    /**
     * Raise only the local rollback-protection generation.
     *
     * This does not alter the authenticated MLS context, epoch secrets, tree,
     * transcript, or Secret Tree frontier. It is used when a separately
     * staged next epoch is adopted after the live current epoch has consumed
     * additional application ratchets.
     */
    rebasePersistenceGeneration(generation: bigint): void {
        this.#ensureActive();
        if (
            this.#transitionState !== "idle" ||
            generation < this.#persistenceGeneration ||
            generation > MAXIMUM_PERSISTENCE_GENERATION
        ) {
            throw new Error("Invalid MLS persistence generation rebase");
        }
        this.#persistenceGeneration = generation;
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
            return this.#stage(next, applied.message.sender);
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

    #stage(next: MlsEpochState, sender: number = this.#localLeaf): StagedEpochTransition {
        if (this.#transitionState !== "preparing") {
            next.destroy();
            throw new Error("MLS epoch transition was not reserved");
        }
        const transition = new StagedEpochTransition(this, next, sender, () => {
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
        return this.#tree;
    }

    #requireCredentialAuthenticator(): (leafNode: MlsLeafNode, leafIndex: number) => boolean {
        return this.#authenticateCredential;
    }
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
