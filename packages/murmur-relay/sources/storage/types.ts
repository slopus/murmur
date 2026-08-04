import type { SignedRelayEvent } from "../protocol/index.js";

/** Result of an atomic idempotent publish. */
export interface PublishOutcome {
    readonly seq: bigint;
    readonly duplicate: boolean;
}

/** Durable identity and original outcome of a published event. */
export interface PublishReceipt {
    readonly seq: bigint;
    readonly fingerprint: Uint8Array;
}

/** Shared one-use protected-read challenge record. */
export interface StoredReadChallenge {
    readonly id: string;
    readonly topicId: string;
    readonly nonce: Uint8Array;
    readonly expiresAt: number;
}

/** Allocation bound applied while materializing one event page. */
export interface PageReadConstraints {
    readonly maximumEncodedBytes: number;
}

/** One retained event associated with its never-reused topic sequence. */
export interface RetainedRelayEvent {
    readonly seq: bigint;
    readonly event: SignedRelayEvent;
}

/**
 * Retained events after a cursor and the current topic head.
 *
 * Sequence gaps are expected after expiration or collapse. `head` is the
 * greatest sequence ever allocated and remains monotonic across those holes.
 */
export interface EventPage {
    readonly events: readonly RetainedRelayEvent[];
    readonly head: bigint;
    /** Whether no further retained event exists after the returned page. */
    readonly exhausted: boolean;
}

/** Atomic persistence operations required by the relay service. */
export interface RelayStore {
    issueReadChallenge(
        challenge: StoredReadChallenge,
        now: number,
        maximumOutstanding: number,
    ): Promise<boolean>;
    consumeReadChallenge(id: string, now: number): Promise<StoredReadChallenge | undefined>;
    readPublishReceipt(topicId: string, id: string): Promise<PublishReceipt | undefined>;
    publish(event: SignedRelayEvent, topicId: string, now: number): Promise<PublishOutcome>;
    readEvents(
        topicId: string,
        since: bigint,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<EventPage>;
    pruneExpired(now: number): Promise<number>;
    health(): Promise<void>;
    close(): Promise<void>;
}
