import type { MurmurClient, PublishResult, ReceivedEvent } from "@murmur/core";
import type { MlsEpochCommitProposal } from "../epoch/index.js";
import type { OpenedMlsApplicationMessage } from "../privateMessage/index.js";
import type { MlsRatchetTree } from "../ratchetTree/index.js";

/** Minimal client surface used by a group channel. */
export type MlsGroupMurmurClient = Pick<MurmurClient, "publish" | "subscribe">;

/** Successfully authenticated MLS application delivery awaiting manual ack. */
export interface OpenedMlsGroupDelivery {
    readonly status: "opened";
    readonly message: OpenedMlsApplicationMessage;
    readonly event: ReceivedEvent["event"];
    readonly persistenceGeneration: bigint;
    /** Ciphertext fingerprint to persist with the epoch and application record. */
    readonly fingerprint: Uint8Array;
    /** Sensitive post-open epoch checkpoint for atomic application persistence. */
    serializeEpoch(): Uint8Array;
    /** Confirm the checkpoint and application record committed atomically. */
    markPersisted(): void;
    acknowledge(): Promise<void>;
}

/** Replay of an application ciphertext already represented by durable state. */
export interface AppliedMlsGroupApplicationDelivery {
    readonly status: "application-applied";
    readonly fingerprint: Uint8Array;
    readonly event: ReceivedEvent["event"];
    acknowledge(): Promise<void>;
}

/** Current-epoch delivery which could not yet be opened, also awaiting manual ack. */
export interface DeferredMlsGroupDelivery {
    readonly status: "deferred";
    readonly error: Error;
    readonly event: ReceivedEvent["event"];
    acknowledge(): Promise<void>;
}

/** Authenticated group Commit staged until durable application adoption. */
export interface StagedMlsGroupCommitDelivery {
    readonly status: "commit";
    readonly event: ReceivedEvent["event"];
    readonly fingerprint: Uint8Array;
    readonly persistenceGeneration: bigint;
    /** Sensitive staged next-epoch checkpoint for atomic adoption. */
    serializeNextEpoch(): Uint8Array;
    /** Confirm the checkpoint and Commit marker committed atomically. */
    markPersisted(): void;
    adopt(): void;
    cancel(): void;
    acknowledge(): Promise<void>;
}

/** Replay of a Commit already represented by the durable current epoch. */
export interface AppliedMlsGroupCommitDelivery {
    readonly status: "applied";
    readonly fingerprint: Uint8Array;
    readonly event: ReceivedEvent["event"];
    acknowledge(): Promise<void>;
}

/** Authenticated Commit which removes the local member from the next epoch. */
export interface RemovedMlsGroupDelivery {
    readonly status: "removed";
    readonly fingerprint: Uint8Array;
    readonly event: ReceivedEvent["event"];
    /** Confirm durable group retirement before secret destruction and ack. */
    markPersisted(): void;
    /** Release the current epoch when durable retirement failed. */
    cancel(): void;
    acknowledge(): Promise<void>;
}

/** Outbound application ciphertext and its post-ratchet durable checkpoint. */
export interface PreparedMlsGroupApplication {
    readonly payload: Uint8Array;
    readonly fingerprint: Uint8Array;
    readonly persistenceGeneration: bigint;
    /** Sensitive current-epoch bytes to persist atomically with `payload`. */
    serializeEpoch(): Uint8Array;
    /** Confirm the checkpoint and exact outbound event committed atomically. */
    markPersisted(): void;
    publish(client: MlsGroupMurmurClient): Promise<PublishResult>;
    /** Resolve a prior ambiguous publish with its matching retained retry. */
    confirmPublished(result: PublishResult): void;
    /** Burn the unused generation and release the channel before publication. */
    cancel(): void;
    /** Destroy in-memory state after its checkpoint/outbox is durably recoverable. */
    abandonPersisted(): void;
}

/** Result of dispatching one transport delivery to a current-epoch channel. */
export type MlsGroupDelivery =
    | OpenedMlsGroupDelivery
    | AppliedMlsGroupApplicationDelivery
    | StagedMlsGroupCommitDelivery
    | AppliedMlsGroupCommitDelivery
    | RemovedMlsGroupDelivery
    | DeferredMlsGroupDelivery;

/** Published relay result returned by prepared application and Commit handles. */
export type MlsGroupPublishResult = PublishResult;

/** Outbound Commit bytes and adoption handle, to be durably published in order. */
export interface PreparedMlsGroupCommit {
    readonly payload: Uint8Array;
    readonly fingerprint: Uint8Array;
    readonly welcome?: Uint8Array;
    readonly tree: MlsRatchetTree;
    readonly addedLeaves: readonly number[];
    readonly removedLeaves: readonly number[];
    /** Monotonic generation of the staged next-epoch checkpoint. */
    readonly persistenceGeneration: bigint;
    /** Sensitive next-epoch bytes to persist atomically with `payload`. */
    serializeNextEpoch(): Uint8Array;
    /** Confirm the checkpoint, Commit marker, and exact event committed atomically. */
    markPersisted(): void;
    publish(client: MlsGroupMurmurClient): Promise<PublishResult>;
    /** Resolve a prior ambiguous publish with its matching `retryOutbound()` result. */
    confirmPublished(result: PublishResult): void;
    adopt(): void;
    cancel(): void;
    /** Destroy both staged/current in-memory epochs without altering durable state. */
    abandonPersisted(): void;
}

/** Full Commit proposal type exposed by the group channel. */
export type MlsGroupCommitProposal = MlsEpochCommitProposal;
