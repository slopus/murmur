import type { IdentityKeyPair } from "../crypto/index.js";
import { identityId } from "../identity/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    createRelayEvent,
    relayTopicId,
    verifyRelayEvent,
    type RelayTopic,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicAccess,
} from "../transport/index.js";
import { utf8Decode, utf8Encode } from "../utils/index.js";
import type { PublishResult, ReceivedEvent, Subscription, SyncResult } from "./types.js";

export type { PublishResult, ReceivedEvent, Subscription, SyncResult } from "./types.js";

const DEFAULT_EVENT_PAGE_LIMIT = 100;

function isAborted(signal: AbortSignal | undefined): boolean {
    return signal?.aborted === true;
}

function cursorBytes(value: bigint): Uint8Array {
    return utf8Encode(value.toString());
}

function parseCursor(value: Uint8Array | undefined): bigint {
    if (value === undefined) return 0n;
    const text = utf8Decode(value);
    if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error("Invalid persisted topic cursor");
    return BigInt(text);
}

/**
 * Stateful client for exactly one relay.
 *
 * The client owns topic cursors in application-provided persistence. It does
 * not implement relay failover, multi-relay ordering, chat semantics, or an
 * implicit retry queue.
 */
export class MurmurClient {
    readonly #identity: IdentityKeyPair;
    readonly #store: MurmurStore;
    readonly #transport: RelayTransport;
    readonly #subscriptions = new Map<string, Subscription>();
    readonly #cursorPrefix: string;

    constructor(options: {
        readonly identity: IdentityKeyPair;
        readonly store: MurmurStore;
        readonly transport: RelayTransport;
    }) {
        this.#identity = options.identity;
        this.#store = options.store;
        this.#transport = options.transport;
        this.#cursorPrefix = `client/${identityId(options.identity)}/cursor/`;
    }

    /** Follow one typed topic locally. No subscription state is sent to the relay. */
    subscribe(access: TopicAccess): void {
        if (
            access.topic.type !== "write" &&
            (access.readSecretKey === undefined || access.readSecretKey.length !== 32)
        ) {
            throw new Error("Protected topic requires its read secret key");
        }
        this.#subscriptions.set(relayTopicId(access.topic), access);
    }

    /** Stop following a topic without deleting its durable cursor. */
    unsubscribe(topic: RelayTopic): void {
        this.#subscriptions.delete(relayTopicId(topic));
    }

    /** Delete one topic cursor inside the transaction retiring its local replica. */
    async retireTopicCursor(transaction: StoreTransaction, topic: RelayTopic): Promise<void> {
        await transaction.delete(this.#cursorKey(topic));
    }

    /** Sign and publish opaque bytes to the single configured relay. */
    async publish(
        topic: RelayTopic,
        payload: Uint8Array,
        options: {
            readonly expiresAt?: number;
            readonly collapseKey?: Uint8Array;
        } = {},
    ): Promise<PublishResult> {
        return this.publishEvent(createRelayEvent(this.#identity, topic, payload, options));
    }

    /** Publish one pre-created event with no hidden retry or failover behavior. */
    async publishEvent(event: SignedRelayEvent): Promise<PublishResult> {
        if (!verifyRelayEvent(event)) throw new Error("Invalid prepared relay event");
        return { event, outcome: await this.#transport.publish(event) };
    }

    /**
     * Read one page per followed topic.
     *
     * Expiration/collapse holes are skipped. The cursor for an empty retained
     * suffix advances to the topic head immediately because there is no
     * application state to commit for absent events.
     */
    async sync(waitMilliseconds: number = 0, signal?: AbortSignal): Promise<SyncResult> {
        const events: ReceivedEvent[] = [];
        const subscriptions = [...this.#subscriptions].sort(([left], [right]) =>
            left.localeCompare(right),
        );
        const reads = await Promise.all(
            subscriptions.map(async ([topicId, access]) => {
                const cursorKey = `${this.#cursorPrefix}${topicId}`;
                const cursor = parseCursor(await this.#store.get(cursorKey));
                return {
                    topicId,
                    cursorKey,
                    cursor,
                    page: await this.#transport.readEvents(
                        access,
                        cursor,
                        DEFAULT_EVENT_PAGE_LIMIT,
                        waitMilliseconds,
                        signal,
                    ),
                };
            }),
        );
        for (const { topicId, cursorKey, cursor, page } of reads) {
            if (page.head < cursor) {
                throw new Error("Relay returned a topic head behind the durable cursor");
            }
            if (page.events.length === 0) {
                if (page.head > cursor) await this.#store.set(cursorKey, cursorBytes(page.head));
                continue;
            }
            let previousSequence = cursor;
            for (let index = 0; index < page.events.length; index += 1) {
                const retained = page.events[index];
                if (
                    retained === undefined ||
                    retained.seq <= previousSequence ||
                    relayTopicId(retained.event.topic) !== topicId ||
                    !verifyRelayEvent(retained.event)
                ) {
                    throw new Error("Relay returned an invalid ordered event page");
                }
                const isLast = index === page.events.length - 1;
                const target =
                    isLast && page.events.length < DEFAULT_EVENT_PAGE_LIMIT
                        ? page.head
                        : retained.seq;
                const expectedCursor = previousSequence;
                events.push({
                    seq: retained.seq,
                    event: retained.event,
                    advanceCursor: async (transaction): Promise<void> => {
                        const current = parseCursor(await transaction.get(cursorKey));
                        if (current >= target) return;
                        if (current !== expectedCursor) {
                            throw new Error("Cannot skip an earlier retained relay event");
                        }
                        await transaction.set(cursorKey, cursorBytes(target));
                    },
                });
                previousSequence = retained.seq;
            }
        }
        return { events };
    }

    /** Yield ordered durable events through long polling. */
    async *events(
        signal?: AbortSignal,
        waitMilliseconds: number = 25_000,
    ): AsyncIterable<ReceivedEvent> {
        while (!isAborted(signal)) {
            const result = await this.sync(waitMilliseconds, signal);
            for (const event of result.events) {
                if (isAborted(signal)) return;
                yield event;
            }
        }
    }

    #cursorKey(topic: RelayTopic): string {
        return `${this.#cursorPrefix}${relayTopicId(topic)}`;
    }
}
