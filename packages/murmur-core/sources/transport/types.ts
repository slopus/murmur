/** Maximum opaque event payload accepted by the default protocol profile. */
export const MAX_RELAY_EVENT_PAYLOAD_BYTES = 1024 * 1024;
/** Maximum ciphertext blob accepted by the default relay protocol profile. */
export const MAX_RELAY_BLOB_BYTES = 64 * 1024 * 1024;
/** Maximum opaque ephemeral frame accepted by the default relay profile. */
export const MAX_RELAY_EPHEMERAL_FRAME_BYTES = 128 * 1024;

/** A relay supplied blob failed its size or content-address integrity checks. */
export class RelayBlobIntegrityError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "RelayBlobIntegrityError";
    }
}

/** Public signing identity attached to every relay write. */
export interface RelayAuthor {
    readonly signingKey: Uint8Array;
}

/** Optimistic replacement or deletion of the topic snapshot. */
export interface SnapshotMutation {
    readonly expectedVersion: number;
    readonly bytes?: Uint8Array;
}

/** Append one new opaque list element at the end of the topic order. */
export interface AppendListOperation {
    readonly op: "append";
    readonly id: string;
    readonly bytes: Uint8Array;
}

/** Replace one existing opaque list element without changing its position. */
export interface ReplaceListOperation {
    readonly op: "replace";
    readonly id: string;
    readonly expectedVersion?: number;
    readonly bytes: Uint8Array;
}

/** Delete one existing opaque list element. */
export interface DeleteListOperation {
    readonly op: "delete";
    readonly id: string;
    readonly expectedVersion?: number;
}

/** One ordered list mutation carried by a signed event. */
export type ListOperation = AppendListOperation | ReplaceListOperation | DeleteListOperation;

/** Complete authenticated event accepted by the relay. */
export interface SignedRelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly author: RelayAuthor;
    readonly createdAt: number;
    readonly payload: Uint8Array;
    readonly snapshot?: SnapshotMutation;
    readonly list?: readonly ListOperation[];
    readonly signature: Uint8Array;
}

/** Content-addressed ciphertext retained independently of topics. */
export interface RelayBlob {
    readonly id: string;
    readonly bytes: Uint8Array;
}

/** Result of an atomic publish, preserved exactly for idempotent retries. */
export interface PublishOutcome {
    readonly seq: bigint;
    readonly duplicate: boolean;
    readonly snapshotVersion?: bigint;
}

/** Current opaque snapshot with its last mutation version. */
export interface TopicSnapshot {
    readonly version: bigint;
    readonly bytes: Uint8Array;
}

/** Current opaque list element in relay-assigned order. */
export interface ListElement {
    readonly id: string;
    readonly version: bigint;
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

/** Browser-safe fetch signature accepted by the HTTP transport. */
export type RelayFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

/**
 * Callbacks for one live topic stream.
 *
 * Every handler is optional so a caller can observe only the ephemeral signals
 * it cares about. The transport never buffers frames on the caller's behalf:
 * each callback runs synchronously as its named SSE event is parsed.
 */
export interface RelayStreamHandlers {
    /** The stream is live; emitted once before any other event. */
    readonly onReady?: () => void;
    /** One decoded opaque ephemeral frame. */
    readonly onFrame?: (bytes: Uint8Array) => void;
    /** Durable events may be available; the caller should synchronize now. */
    readonly onWake?: () => void;
    /** The relay dropped `frames` queued frames for this subscriber. */
    readonly onDrop?: (frames: number) => void;
}

/** Relay boundary for signed topic state and link-mediated blob transfers. */
export interface RelayTransport {
    readonly id: string;
    publish(event: SignedRelayEvent): Promise<PublishOutcome>;
    readState(topic: string, limit?: number): Promise<TopicState | undefined>;
    readList(topic: string, cursor?: string, limit?: number): Promise<ListPage | undefined>;
    readEvents(
        topic: string,
        since: bigint,
        limit?: number,
        wait?: number,
        signal?: AbortSignal,
    ): Promise<EventPage | undefined>;
    /** Request an upload link and transfer one content-addressed ciphertext blob. */
    putBlob(blob: RelayBlob): Promise<void>;
    /**
     * Request a download link and return one validated ciphertext blob when present.
     *
     * When provided, `expectedBytes` is an exact ciphertext length, not only
     * an upper bound. Implementations must reject a larger response before
     * allocating a concatenated result.
     */
    getBlob(id: string, expectedBytes?: number): Promise<RelayBlob | undefined>;
    /**
     * Publish one opaque ephemeral frame to a topic's live stream subscribers.
     *
     * Optional so existing transports keep compiling. Nothing is stored: the
     * returned number is the relay's informational count of local subscribers
     * enqueued, never a delivery guarantee.
     */
    publishEphemeral?(topic: string, frame: Uint8Array, signal?: AbortSignal): Promise<number>;
    /**
     * Open one live topic stream and dispatch its events until it ends.
     *
     * Optional so existing transports keep compiling. The returned promise
     * resolves when the stream ends (including a prompt `signal` abort) and
     * rejects on transport failure.
     */
    openStream?(topic: string, handlers: RelayStreamHandlers, signal: AbortSignal): Promise<void>;
}
