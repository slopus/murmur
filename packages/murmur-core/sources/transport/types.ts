/** A publicly readable topic whose durable writes require this key. */
export interface WriteTopic {
    readonly type: "write";
    readonly name: string;
    readonly writeKey: Uint8Array;
}

/** A publicly writable topic whose reads require this key. */
export interface ReadTopic {
    readonly type: "read";
    readonly name: string;
    readonly readKey: Uint8Array;
}

/** A topic whose reads and writes require designated keys. */
export interface ReadWriteTopic {
    readonly type: "read-write";
    readonly name: string;
    readonly readKey: Uint8Array;
    readonly writeKey: Uint8Array;
}

/** Typed, named, key-scoped relay topic descriptor. */
export type RelayTopic = WriteTopic | ReadTopic | ReadWriteTopic;

/** Secret capability material used only by the client. */
export interface TopicAccess {
    readonly topic: RelayTopic;
    readonly readSecretKey?: Uint8Array;
    readonly writeSecretKey?: Uint8Array;
}

/** Minimal Ed25519 signing material accepted when constructing an event. */
export interface RelaySigningKey {
    readonly signingKey: Uint8Array;
    readonly signingSecretKey: Uint8Array;
}

/** Complete signed durable relay event. */
export interface SignedRelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: RelayTopic;
    readonly author: { readonly signingKey: Uint8Array };
    readonly createdAt: number;
    readonly expiresAt?: number;
    readonly collapseKey?: Uint8Array;
    readonly payload: Uint8Array;
    readonly signature: Uint8Array;
}

/** Idempotent publication outcome. */
export interface PublishOutcome {
    readonly seq: bigint;
    readonly duplicate: boolean;
}

/** One retained event at its never-reused topic sequence. */
export interface RetainedRelayEvent {
    readonly seq: bigint;
    readonly event: SignedRelayEvent;
}

/** One event page; sequence holes are legal after expiration or collapse. */
export interface EventPage {
    readonly events: readonly RetainedRelayEvent[];
    readonly head: bigint;
    /** Whether no further retained event exists after the returned page. */
    readonly exhausted: boolean;
}

/** Browser-safe fetch signature accepted by the HTTP transport. */
export type RelayFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/** The single relay boundary used by a stateful Murmur client. */
export interface RelayTransport {
    publish(event: SignedRelayEvent): Promise<PublishOutcome>;
    readEvents(
        access: TopicAccess,
        since: bigint,
        limit?: number,
        waitMilliseconds?: number,
        signal?: AbortSignal,
    ): Promise<EventPage>;
}
