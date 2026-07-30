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

/** Result of dispatching one transport delivery to a current-epoch channel. */
export type MlsGroupDelivery =
    | OpenedMlsGroupDelivery
    | StagedMlsGroupCommitDelivery
    | AppliedMlsGroupCommitDelivery
    | DeferredMlsGroupDelivery;

/** Return type retained for the send method's public contract. */
export type MlsGroupPublishResult = PublishResult;

/** Outbound Commit bytes and adoption handle, to be durably published in order. */
export interface PreparedMlsGroupCommit {
    readonly payload: Uint8Array;
    readonly welcome?: Uint8Array;
    readonly tree: MlsRatchetTree;
    readonly addedLeaves: readonly number[];
    readonly removedLeaves: readonly number[];
    publish(client: MlsGroupMurmurClient): Promise<PublishResult>;
    /** Resolve a prior ambiguous publish with its matching `retryOutbound()` result. */
    confirmPublished(result: PublishResult): void;
    adopt(): void;
    cancel(): void;
}

/** Full Commit proposal type exposed by the group channel. */
export type MlsGroupCommitProposal = MlsEpochCommitProposal;
