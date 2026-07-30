import {
    encodeBase64Url,
    equalBytes,
    hashBytes,
    type PublishResult,
    type ReceivedEvent,
} from "@murmur/core";
import { MlsEpochState, type MlsEpochCommitProposal } from "../epoch/index.js";
import type {
    MlsGroupDelivery,
    MlsGroupMurmurClient,
    MlsGroupPublishResult,
    PreparedMlsGroupCommit,
} from "./types.js";

export type {
    DeferredMlsGroupDelivery,
    AppliedMlsGroupCommitDelivery,
    MlsGroupDelivery,
    MlsGroupCommitProposal,
    MlsGroupMurmurClient,
    MlsGroupPublishResult,
    OpenedMlsGroupDelivery,
    PreparedMlsGroupCommit,
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
        result.event.recipients.length !== 0 ||
        !equalBytes(hashBytes(result.event.payload), fingerprint)
    ) {
        throw new Error("Publish result does not match the prepared MLS Commit");
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
 * `ReceivedEvent` to its channels. This preserves the client's cross-group
 * in-flight deduplication and explicit acknowledgement semantics.
 */
export class MlsGroupChannel {
    #epoch: MlsEpochState;
    readonly #topic: string;
    readonly #appliedCommits = new Map<string, Uint8Array>();
    #pendingOutbound = false;

    constructor(epoch: MlsEpochState, appliedCommitFingerprints: readonly Uint8Array[] = []) {
        if (
            appliedCommitFingerprints.length > MAXIMUM_APPLIED_COMMIT_MARKERS ||
            appliedCommitFingerprints.some((fingerprint) => fingerprint.length !== 32)
        ) {
            throw new Error("Invalid applied MLS Commit fingerprints");
        }
        this.#epoch = epoch;
        this.#topic = mlsGroupTopic(epoch.context.groupId);
        for (const fingerprint of appliedCommitFingerprints) {
            this.#appliedCommits.set(encodeBase64Url(fingerprint), fingerprint.slice());
        }
    }

    /** Opaque relay topic shared by every epoch of this group. */
    get topic(): string {
        return this.#topic;
    }

    /** Commit replay markers which must be persisted atomically with the epoch. */
    get appliedCommitFingerprints(): readonly Uint8Array[] {
        return [...this.#appliedCommits.values()].map((fingerprint) => fingerprint.slice());
    }

    /** Forget one replay marker only after every relevant relay delivery is acknowledged. */
    forgetAppliedCommit(fingerprint: Uint8Array): void {
        if (fingerprint.length !== 32) {
            throw new Error("Invalid applied MLS Commit fingerprint");
        }
        this.#appliedCommits.delete(encodeBase64Url(fingerprint));
    }

    /** Subscribe the local Murmur identity to the group's relay topic. */
    async subscribe(client: MlsGroupMurmurClient): Promise<void> {
        await client.subscribe(this.#topic);
    }

    /** Encrypt and publish current-epoch application content. */
    async send(
        client: MlsGroupMurmurClient,
        applicationData: Uint8Array,
        authenticatedData: Uint8Array = new Uint8Array(),
        paddingBytes: number = 0,
    ): Promise<MlsGroupPublishResult> {
        return client.publish(
            this.#topic,
            this.#epoch.seal(applicationData, authenticatedData, paddingBytes),
        );
    }

    /**
     * Stage a full Add/Remove Commit for ordered durable publication.
     *
     * The caller persists the returned public tree and Welcome, calls the
     * handle's `publish()`, then calls `adopt()`. A pre-publication abort calls
     * `cancel()`. Network-ambiguous publication must remain staged until the
     * retained Murmur outbox is resolved.
     */
    prepareCommit(
        proposals: readonly MlsEpochCommitProposal[],
        authenticatedData: Uint8Array = new Uint8Array(),
    ): PreparedMlsGroupCommit {
        if (this.#pendingOutbound) {
            throw new Error("MLS group channel already has a pending outbound Commit");
        }
        const prepared = this.#epoch.prepareCommit(proposals, authenticatedData);
        this.#pendingOutbound = true;
        let publication: "prepared" | "publishing" | "ambiguous" | "confirmed" = "prepared";
        let settled = false;
        const commit = prepared.commit.slice();
        const fingerprint = hashBytes(commit);
        return {
            payload: commit.slice(),
            ...(prepared.welcome === undefined ? {} : { welcome: prepared.welcome }),
            tree: prepared.tree,
            addedLeaves: prepared.addedLeaves,
            removedLeaves: prepared.removedLeaves,
            publish: async (client): Promise<MlsGroupPublishResult> => {
                if (settled || publication !== "prepared") {
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
                const inserted = this.#recordAppliedCommit(fingerprint);
                try {
                    this.#epoch = prepared.transition.commit();
                } catch (error: unknown) {
                    this.#rollbackAppliedCommit(fingerprint, inserted);
                    throw error;
                }
                settled = true;
                this.#pendingOutbound = false;
            },
            cancel: (): void => {
                if (settled || publication !== "prepared") {
                    throw new Error(`MLS group Commit publication is ${publication}`);
                }
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
     * deliberately not auto-acknowledged: it may be a valid future-epoch event.
     */
    handle(received: ReceivedEvent): MlsGroupDelivery | undefined {
        if (received.event.topic !== this.#topic) {
            return undefined;
        }
        try {
            if (isPublicMlsMessage(received.event.payload)) {
                const fingerprint = hashBytes(received.event.payload);
                if (this.#appliedCommits.has(encodeBase64Url(fingerprint))) {
                    return {
                        status: "applied",
                        fingerprint: fingerprint.slice(),
                        event: received.event,
                        acknowledge: received.acknowledge,
                    };
                }
                const transition = this.#epoch.applyCommit(received.event.payload);
                let state: "staged" | "adopted" | "cancelled" = "staged";
                return {
                    status: "commit",
                    event: received.event,
                    adopt: (): void => {
                        if (state !== "staged") {
                            throw new Error(`MLS group Commit delivery is ${state}`);
                        }
                        const inserted = this.#recordAppliedCommit(fingerprint);
                        try {
                            this.#epoch = transition.commit();
                        } catch (error: unknown) {
                            this.#rollbackAppliedCommit(fingerprint, inserted);
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
                    acknowledge: async (): Promise<void> => {
                        if (state !== "adopted") {
                            throw new Error(
                                "MLS group Commit must be adopted before acknowledgment",
                            );
                        }
                        await received.acknowledge();
                    },
                };
            }
            return {
                status: "opened",
                message: this.#epoch.open(received.event.payload),
                event: received.event,
                acknowledge: received.acknowledge,
            };
        } catch (error: unknown) {
            return {
                status: "deferred",
                error: error instanceof Error ? error : new Error("MLS group open failed"),
                event: received.event,
                acknowledge: received.acknowledge,
            };
        }
    }

    /** Destroy the owned current epoch. */
    destroy(): void {
        if (this.#pendingOutbound) {
            throw new Error("Cannot destroy MLS group channel with pending outbound Commit");
        }
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
