import {
    encodeBase64Url,
    equalBytes,
    hashBytes,
    zeroBytes,
    type PublishResult,
    type ReceivedEvent,
} from "@slopus/murmur";
import { decodeMlsTreeCommit, MlsLocalMemberRemovedError } from "../commit/index.js";
import { MlsEpochState, type MlsEpochCommitProposal } from "../epoch/index.js";
import type {
    MlsGroupDelivery,
    MlsGroupCommitAuthor,
    MlsGroupMurmurClient,
    MlsGroupPublishResult,
    PreparedMlsGroupApplication,
    PreparedMlsGroupCommit,
} from "./types.js";

export type {
    AppliedMlsGroupApplicationDelivery,
    DeferredMlsGroupDelivery,
    AppliedMlsGroupCommitDelivery,
    MlsGroupDelivery,
    MlsGroupCommitAuthor,
    MlsGroupCommitProposal,
    MlsGroupMurmurClient,
    MlsGroupPublishResult,
    OpenedMlsGroupDelivery,
    PreparedMlsGroupApplication,
    PreparedMlsGroupCommit,
    RemovedMlsGroupDelivery,
    StagedMlsGroupCommitDelivery,
} from "./types.js";

const MLS_PROTOCOL_VERSION = 1;
const MLS_WIRE_FORMAT_PUBLIC_MESSAGE = 1;
const MAXIMUM_APPLIED_COMMIT_MARKERS = 100_000;

function isPublicMlsMessage(payload: Uint8Array): boolean {
    return (
        payload.length >= 4 &&
        (((payload[0] ?? 0) << 8) | (payload[1] ?? 0)) === MLS_PROTOCOL_VERSION &&
        (((payload[2] ?? 0) << 8) | (payload[3] ?? 0)) === MLS_WIRE_FORMAT_PUBLIC_MESSAGE
    );
}

function validatePublishResult(
    result: PublishResult,
    topic: string,
    fingerprint: Uint8Array,
): void {
    if (
        result.publishedRelayIds.length === 0 ||
        result.event.topic !== topic ||
        !equalBytes(hashBytes(result.event.payload), fingerprint)
    ) {
        throw new Error("Publish result does not match the prepared MLS event");
    }
}

/** Stable opaque relay topic for one MLS group identifier. */
export function mlsGroupTopic(groupId: Uint8Array): string {
    if (groupId.length === 0 || groupId.length > 255) {
        throw new Error("Invalid MLS group identifier");
    }
    return `mls:${encodeBase64Url(hashBytes(groupId))}`;
}

/**
 * Relay adapter for one current MLS epoch.
 *
 * The application calls `MurmurClient.sync()` once and dispatches each
 * `ReceivedEvent` to its channels. Cursor advancement remains coupled to the
 * application's durable transaction.
 */
export class MlsGroupChannel {
    #epoch: MlsEpochState;
    readonly #topic: string;
    readonly #appliedCommits = new Map<string, Uint8Array>();
    readonly #appliedApplications = new Map<string, Uint8Array>();
    #pendingOutbound = false;
    #pendingInbound = false;
    #pendingInboundCheckpoint: Uint8Array | undefined;

    constructor(
        epoch: MlsEpochState,
        appliedCommitFingerprints: readonly Uint8Array[] = [],
        appliedApplicationFingerprints: readonly Uint8Array[] = [],
    ) {
        if (
            appliedCommitFingerprints.length > MAXIMUM_APPLIED_COMMIT_MARKERS ||
            appliedCommitFingerprints.some((fingerprint) => fingerprint.length !== 32) ||
            appliedApplicationFingerprints.length > MAXIMUM_APPLIED_COMMIT_MARKERS ||
            appliedApplicationFingerprints.some((fingerprint) => fingerprint.length !== 32)
        ) {
            throw new Error("Invalid applied MLS fingerprints");
        }
        this.#epoch = epoch;
        this.#topic = mlsGroupTopic(epoch.context.groupId);
        for (const fingerprint of appliedCommitFingerprints) {
            this.#appliedCommits.set(encodeBase64Url(fingerprint), fingerprint.slice());
        }
        for (const fingerprint of appliedApplicationFingerprints) {
            this.#appliedApplications.set(encodeBase64Url(fingerprint), fingerprint.slice());
        }
    }

    /** Opaque relay topic shared by every epoch of this group. */
    get topic(): string {
        return this.#topic;
    }

    /** Defensive copy of the stable MLS group identifier. */
    get groupId(): Uint8Array {
        return this.#epoch.groupId;
    }

    /** Monotonic generation of the currently owned epoch. */
    get persistenceGeneration(): bigint {
        return this.#epoch.persistenceGeneration;
    }

    /** Current RFC epoch number. */
    get epoch(): bigint {
        return this.#epoch.context.epoch;
    }

    /** Defensive member signing-key view indexed by MLS leaf number. */
    get memberSignatureKeys(): readonly (Uint8Array | undefined)[] {
        return this.#epoch.memberSignatureKeys;
    }

    /**
     * Resolve and validate a current-epoch Commit author without applying it.
     *
     * Higher-level protocols use this before `handle()` to enforce a stricter
     * committer ACL than ordinary MLS membership.
     */
    inspectCommitAuthor(payload: Uint8Array): MlsGroupCommitAuthor {
        if (!isPublicMlsMessage(payload)) {
            throw new Error("MLS payload is not a Commit");
        }
        const message = decodeMlsTreeCommit(payload);
        const signingKey = this.#epoch.memberSignatureKeys[message.sender];
        if (
            !equalBytes(message.groupId, this.#epoch.groupId) ||
            message.epoch > this.#epoch.context.epoch ||
            signingKey === undefined
        ) {
            throw new Error("MLS Commit does not have a current group author");
        }
        return {
            sender: message.sender,
            signingKey: signingKey.slice(),
        };
    }

    /** Serialize the current epoch after an inbound delivery or adoption. */
    serializeEpoch(): Uint8Array {
        if (this.#pendingOutbound || this.#pendingInbound) {
            throw new Error("MLS group channel has a pending event");
        }
        return this.#epoch.serialize();
    }

    /** Commit replay markers which must be persisted atomically with the epoch. */
    get appliedCommitFingerprints(): readonly Uint8Array[] {
        return [...this.#appliedCommits.values()].map((fingerprint) => fingerprint.slice());
    }

    /** Application replay markers persisted atomically with the epoch. */
    get appliedApplicationFingerprints(): readonly Uint8Array[] {
        return [...this.#appliedApplications.values()].map((fingerprint) => fingerprint.slice());
    }

    /** Forget one replay marker only after every relevant relay cursor has advanced. */
    forgetAppliedCommit(fingerprint: Uint8Array): void {
        if (fingerprint.length !== 32) {
            throw new Error("Invalid applied MLS Commit fingerprint");
        }
        this.#appliedCommits.delete(encodeBase64Url(fingerprint));
    }

    /** Forget an application replay marker after all relay echo cursors advance. */
    forgetAppliedApplication(fingerprint: Uint8Array): void {
        if (fingerprint.length !== 32) {
            throw new Error("Invalid applied MLS application fingerprint");
        }
        this.#appliedApplications.delete(encodeBase64Url(fingerprint));
    }

    /** Subscribe the local Murmur identity to the group's relay topic. */
    async subscribe(client: MlsGroupMurmurClient): Promise<void> {
        await client.subscribe(this.#topic);
    }

    /**
     * Prepare application content for durable publication.
     *
     * Persist `payload`, `serializeEpoch()`, and `persistenceGeneration`
     * atomically before calling `publish()`.
     */
    prepareSend(
        applicationData: Uint8Array,
        authenticatedData: Uint8Array = new Uint8Array(),
        paddingBytes: number = 0,
    ): PreparedMlsGroupApplication {
        if (this.#pendingOutbound || this.#pendingInbound) {
            throw new Error("MLS group channel has a pending event");
        }
        if (this.#appliedApplications.size >= MAXIMUM_APPLIED_COMMIT_MARKERS) {
            throw new Error("Too many outstanding applied MLS application markers");
        }
        const payload = this.#epoch.seal(applicationData, authenticatedData, paddingBytes);
        const checkpoint = this.#epoch.serialize();
        const persistenceGeneration = this.#epoch.persistenceGeneration;
        const fingerprint = hashBytes(payload);
        const fingerprintId = encodeBase64Url(fingerprint);
        this.#pendingOutbound = true;
        let publication:
            | "prepared"
            | "persisted"
            | "publishing"
            | "ambiguous"
            | "confirmed"
            | "cancelled"
            | "abandoned" = "prepared";
        let settled = false;
        let markerInserted = false;
        const settle = (): void => {
            zeroBytes(checkpoint);
            settled = true;
            this.#pendingOutbound = false;
        };
        return {
            payload: payload.slice(),
            fingerprint: fingerprint.slice(),
            persistenceGeneration,
            serializeEpoch: (): Uint8Array => {
                if (settled) {
                    throw new Error(`MLS group application publication is ${publication}`);
                }
                return checkpoint.slice();
            },
            markPersisted: (): void => {
                if (settled || publication !== "prepared") {
                    throw new Error(`MLS group application publication is ${publication}`);
                }
                if (!this.#appliedApplications.has(fingerprintId)) {
                    this.#appliedApplications.set(fingerprintId, fingerprint.slice());
                    markerInserted = true;
                }
                publication = "persisted";
            },
            publish: async (client): Promise<MlsGroupPublishResult> => {
                if (settled || publication !== "persisted") {
                    throw new Error(`MLS group application publication is ${publication}`);
                }
                publication = "publishing";
                try {
                    const result = await client.publish(this.#topic, payload.slice());
                    validatePublishResult(result, this.#topic, fingerprint);
                    publication = "confirmed";
                    settle();
                    return result;
                } catch (error: unknown) {
                    publication = "ambiguous";
                    throw error;
                }
            },
            confirmPublished: (result): void => {
                if (settled || publication !== "ambiguous") {
                    throw new Error(`MLS group application publication is ${publication}`);
                }
                validatePublishResult(result, this.#topic, fingerprint);
                publication = "confirmed";
                settle();
            },
            cancel: (): void => {
                if (settled || (publication !== "prepared" && publication !== "persisted")) {
                    throw new Error(`MLS group application publication is ${publication}`);
                }
                publication = "cancelled";
                if (markerInserted) {
                    this.#appliedApplications.delete(fingerprintId);
                }
                settle();
            },
            abandonPersisted: (): void => {
                if (settled) {
                    return;
                }
                if (
                    publication !== "persisted" &&
                    publication !== "ambiguous" &&
                    publication !== "confirmed"
                ) {
                    throw new Error(`MLS group application publication is ${publication}`);
                }
                publication = "abandoned";
                settle();
            },
        };
    }

    /**
     * Stage a full Add/Remove Commit for ordered durable publication.
     *
     * The caller atomically persists the payload, Welcome, replay marker, and
     * `serializeNextEpoch()` checkpoint before `publish()`, then calls
     * `adopt()`. A pre-publication abort calls `cancel()`. Network-ambiguous
     * publication must remain staged until the retained Murmur outbox is
     * resolved.
     */
    prepareCommit(
        proposals: readonly MlsEpochCommitProposal[],
        authenticatedData: Uint8Array = new Uint8Array(),
    ): PreparedMlsGroupCommit {
        if (this.#pendingOutbound || this.#pendingInbound) {
            throw new Error("MLS group channel already has a pending event");
        }
        if (this.#appliedCommits.size >= MAXIMUM_APPLIED_COMMIT_MARKERS) {
            throw new Error("Too many outstanding applied MLS Commit markers");
        }
        const prepared = this.#epoch.prepareCommit(proposals, authenticatedData);
        this.#pendingOutbound = true;
        let publication:
            | "prepared"
            | "persisted"
            | "publishing"
            | "ambiguous"
            | "confirmed"
            | "abandoned" = "prepared";
        let settled = false;
        const commit = prepared.commit.slice();
        const fingerprint = hashBytes(commit);
        const fingerprintId = encodeBase64Url(fingerprint);
        let markerInserted = false;
        return {
            payload: commit.slice(),
            fingerprint: fingerprint.slice(),
            ...(prepared.welcome === undefined ? {} : { welcome: prepared.welcome }),
            tree: prepared.tree,
            addedLeaves: prepared.addedLeaves,
            removedLeaves: prepared.removedLeaves,
            persistenceGeneration: prepared.transition.persistenceGeneration,
            serializeNextEpoch: (): Uint8Array => prepared.transition.serialize(),
            markPersisted: (): void => {
                if (settled || publication !== "prepared") {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
                if (!this.#appliedCommits.has(fingerprintId)) {
                    this.#appliedCommits.set(fingerprintId, fingerprint.slice());
                    markerInserted = true;
                }
                publication = "persisted";
            },
            publish: async (client): Promise<MlsGroupPublishResult> => {
                if (settled || publication !== "persisted") {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
                publication = "publishing";
                try {
                    const result = await client.publish(this.#topic, commit.slice());
                    validatePublishResult(result, this.#topic, fingerprint);
                    publication = "confirmed";
                    return result;
                } catch (error: unknown) {
                    publication = "ambiguous";
                    throw error;
                }
            },
            confirmPublished: (result): void => {
                if (settled || publication !== "ambiguous") {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
                validatePublishResult(result, this.#topic, fingerprint);
                publication = "confirmed";
            },
            adopt: (): void => {
                if (settled || publication !== "confirmed") {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
                try {
                    this.#epoch = prepared.transition.commit();
                } catch (error: unknown) {
                    this.#rollbackAppliedCommit(fingerprint, markerInserted);
                    throw error;
                }
                settled = true;
                this.#pendingOutbound = false;
            },
            cancel: (): void => {
                if (settled || (publication !== "prepared" && publication !== "persisted")) {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
                try {
                    prepared.transition.cancel();
                } finally {
                    this.#rollbackAppliedCommit(fingerprint, markerInserted);
                    settled = true;
                    this.#pendingOutbound = false;
                }
            },
            abandonPersisted: (): void => {
                if (settled) {
                    return;
                }
                if (
                    publication !== "persisted" &&
                    publication !== "ambiguous" &&
                    publication !== "confirmed"
                ) {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
                publication = "abandoned";
                try {
                    prepared.transition.cancel();
                } finally {
                    settled = true;
                    this.#pendingOutbound = false;
                }
            },
        };
    }

    /**
     * Dispatch one already authenticated relay delivery.
     *
     * `undefined` means another channel owns the topic. A deferred result is
     * deliberately not auto-consumed: it may be a valid future-epoch event.
     */
    handle(received: ReceivedEvent): MlsGroupDelivery | undefined {
        if (received.event.topic !== this.#topic) {
            return undefined;
        }
        if (this.#pendingOutbound || this.#pendingInbound) {
            return {
                status: "deferred",
                error: new Error("MLS group channel has a pending event"),
                event: received.event,
                advanceCursor: received.advanceCursor,
            };
        }
        try {
            if (isPublicMlsMessage(received.event.payload)) {
                const fingerprint = hashBytes(received.event.payload);
                if (this.#appliedCommits.has(encodeBase64Url(fingerprint))) {
                    return {
                        status: "applied",
                        fingerprint: fingerprint.slice(),
                        event: received.event,
                        advanceCursor: received.advanceCursor,
                    };
                }
                if (this.#appliedCommits.size >= MAXIMUM_APPLIED_COMMIT_MARKERS) {
                    throw new Error("Too many outstanding applied MLS Commit markers");
                }
                let transition: ReturnType<MlsEpochState["applyCommit"]>;
                try {
                    transition = this.#epoch.applyCommit(received.event.payload);
                } catch (error: unknown) {
                    if (!(error instanceof MlsLocalMemberRemovedError)) {
                        throw error;
                    }
                    this.#pendingInbound = true;
                    let state: "staged" | "persisted" | "cancelled" = "staged";
                    return {
                        status: "removed",
                        event: received.event,
                        fingerprint: fingerprint.slice(),
                        markPersisted: (): void => {
                            if (state !== "staged") {
                                throw new Error(`MLS group removal delivery is ${state}`);
                            }
                            this.#epoch.destroy();
                            this.#pendingInbound = false;
                            state = "persisted";
                        },
                        cancel: (): void => {
                            if (state !== "staged") {
                                throw new Error(`MLS group removal delivery is ${state}`);
                            }
                            this.#pendingInbound = false;
                            state = "cancelled";
                        },
                        advanceCursor: received.advanceCursor,
                    };
                }
                let state: "staged" | "persisted" | "adopted" | "cancelled" = "staged";
                let markerInserted = false;
                return {
                    status: "commit",
                    event: received.event,
                    fingerprint: fingerprint.slice(),
                    persistenceGeneration: transition.persistenceGeneration,
                    serializeNextEpoch: (): Uint8Array => {
                        if (state !== "staged") {
                            throw new Error(`MLS group Commit delivery is ${state}`);
                        }
                        return transition.serialize();
                    },
                    markPersisted: (): void => {
                        if (state !== "staged") {
                            throw new Error(`MLS group Commit delivery is ${state}`);
                        }
                        markerInserted = this.#recordAppliedCommit(fingerprint);
                        state = "persisted";
                    },
                    adopt: (): void => {
                        if (state !== "persisted") {
                            throw new Error(`MLS group Commit delivery is ${state}`);
                        }
                        try {
                            this.#epoch = transition.commit();
                        } catch (error: unknown) {
                            this.#rollbackAppliedCommit(fingerprint, markerInserted);
                            throw error;
                        }
                        state = "adopted";
                    },
                    cancel: (): void => {
                        if (state !== "staged") {
                            throw new Error(`MLS group Commit delivery is ${state}`);
                        }
                        try {
                            transition.cancel();
                        } finally {
                            state = "cancelled";
                        }
                    },
                    advanceCursor: received.advanceCursor,
                };
            }
            const fingerprint = hashBytes(received.event.payload);
            const fingerprintId = encodeBase64Url(fingerprint);
            if (this.#appliedApplications.has(fingerprintId)) {
                return {
                    status: "application-applied",
                    fingerprint: fingerprint.slice(),
                    event: received.event,
                    advanceCursor: received.advanceCursor,
                };
            }
            if (this.#appliedApplications.size >= MAXIMUM_APPLIED_COMMIT_MARKERS) {
                throw new Error("Too many outstanding applied MLS application markers");
            }
            const opened = this.#epoch.openWithCheckpoint(received.event.payload);
            const message = opened.message;
            const checkpoint = opened.state;
            const persistenceGeneration = opened.persistenceGeneration;
            this.#pendingInbound = true;
            this.#pendingInboundCheckpoint = checkpoint;
            let state: "opened" | "persisted" = "opened";
            return {
                status: "opened",
                message,
                event: received.event,
                persistenceGeneration,
                fingerprint: fingerprint.slice(),
                serializeEpoch: (): Uint8Array => {
                    if (state !== "opened") {
                        throw new Error(`MLS group application delivery is ${state}`);
                    }
                    return checkpoint.slice();
                },
                markPersisted: (): void => {
                    if (state !== "opened") {
                        throw new Error(`MLS group application delivery is ${state}`);
                    }
                    this.#appliedApplications.set(fingerprintId, fingerprint.slice());
                    zeroBytes(checkpoint);
                    state = "persisted";
                    this.#pendingInbound = false;
                    this.#pendingInboundCheckpoint = undefined;
                },
                advanceCursor: received.advanceCursor,
            };
        } catch (error: unknown) {
            return {
                status: "deferred",
                error: error instanceof Error ? error : new Error("MLS group open failed"),
                event: received.event,
                advanceCursor: received.advanceCursor,
            };
        }
    }

    /** Destroy the owned current epoch. */
    destroy(): void {
        if (this.#pendingOutbound) {
            throw new Error("Cannot destroy MLS group channel with a pending outbound event");
        }
        if (this.#pendingInboundCheckpoint !== undefined) {
            zeroBytes(this.#pendingInboundCheckpoint);
            this.#pendingInboundCheckpoint = undefined;
        }
        this.#pendingInbound = false;
        this.#epoch.destroy();
    }

    #recordAppliedCommit(fingerprint: Uint8Array): boolean {
        const identifier = encodeBase64Url(fingerprint);
        if (this.#appliedCommits.has(identifier)) {
            return false;
        }
        if (this.#appliedCommits.size >= MAXIMUM_APPLIED_COMMIT_MARKERS) {
            throw new Error("Too many outstanding applied MLS Commit markers");
        }
        this.#appliedCommits.set(identifier, fingerprint.slice());
        return true;
    }

    #rollbackAppliedCommit(fingerprint: Uint8Array, inserted: boolean): void {
        if (inserted) {
            this.#appliedCommits.delete(encodeBase64Url(fingerprint));
        }
    }
}
