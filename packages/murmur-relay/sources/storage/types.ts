import type { RelayBlob, SignedRelayEvent } from "../protocol/index.js";

/** Result of an atomic publish, preserved exactly for idempotent retries. */
export interface PublishOutcome {
    readonly seq: bigint;
    readonly duplicate: boolean;
    readonly snapshotVersion?: bigint;
}

/** Durable identity and original outcome of one successfully published event. */
export interface PublishReceipt {
    readonly seq: bigint;
    readonly fingerprint: Uint8Array;
    readonly snapshotVersion?: bigint;
}

/** Relay policy which a store must enforce inside the publish transaction. */
export interface PublishConstraints {
    readonly maximumElementsPerTopic: number;
}

/** Allocation bound applied while a store materializes one response page. */
export interface PageReadConstraints {
    readonly maximumEncodedBytes: number;
}

/** Current opaque snapshot with its last mutation version and topic sequence. */
export interface TopicSnapshot {
    readonly version: bigint;
    readonly seq: bigint;
    readonly bytes: Uint8Array;
}

/** Current opaque list element in relay-assigned order. */
export interface ListElement {
    readonly id: string;
    readonly version: bigint;
    readonly position: bigint;
    readonly seq: bigint;
    readonly bytes: Uint8Array;
}

/** One stable page of current list elements. */
export interface ListPage {
    readonly elements: readonly ListElement[];
    readonly nextCursor: string | null;
}

/** Snapshot and first list page read at one transactionally consistent sequence. */
export interface TopicState {
    readonly seq: bigint;
    readonly snapshot: TopicSnapshot | null;
    readonly list: ListPage;
}

/** One retained signed mutation associated with its per-topic sequence. */
export interface RetainedRelayEvent {
    readonly seq: bigint;
    readonly event: SignedRelayEvent;
}

/** Bounded retained events plus reset information and the current topic head. */
export interface EventPage {
    readonly events: readonly RetainedRelayEvent[];
    readonly reset: boolean;
    readonly seq: bigint;
}

/** Counts returned after dropping inactive topic state. */
export interface PruneResult {
    readonly topics: number;
}

/** Atomic persistence operations required by the relay service. */
export interface RelayStore {
    readPublishReceipt(topic: string, id: string): Promise<PublishReceipt | undefined>;
    publish(
        event: SignedRelayEvent,
        now: number,
        constraints: PublishConstraints,
    ): Promise<PublishOutcome>;
    readState(
        topic: string,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<TopicState | undefined>;
    readList(
        topic: string,
        cursor: string | undefined,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<ListPage | undefined>;
    readEvents(
        topic: string,
        since: bigint,
        limit: number,
        constraints: PageReadConstraints,
    ): Promise<EventPage | undefined>;
    putBlob(blob: RelayBlob): Promise<void>;
    getBlob(id: string): Promise<RelayBlob | undefined>;
    pruneEvents(olderThan: number): Promise<number>;
    pruneInactiveTopics(olderThan: number): Promise<PruneResult>;
    health(): Promise<void>;
    close(): Promise<void>;
}
