import type { IdentityKeyPair } from "../crypto/index.js";
import { ed25519 } from "@noble/curves/ed25519";
import { identityId } from "../identity/index.js";
import type { MurmurStore, StoreTransaction } from "../storage/index.js";
import {
    createRelayEvent,
    relayTopicId,
    verifyRelayEvent,
    type RelaySigningKey,
    type RelayTopic,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicAccess,
} from "../transport/index.js";
import { equalBytes, utf8Decode, utf8Encode } from "../utils/index.js";
import type { PublishResult, ReceivedEvent, Subscription, SyncResult } from "./types.js";

export type { PublishResult, ReceivedEvent, Subscription, SyncResult } from "./types.js";

const DEFAULT_EVENT_PAGE_LIMIT = 100;
const MAXIMUM_SEQUENCE = 9_223_372_036_854_775_807n;

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
    const cursor = BigInt(text);
    if (cursor > MAXIMUM_SEQUENCE) throw new Error("Persisted topic cursor exceeds int64");
    return cursor;
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
    readonly #pending = new Map<string, Set<bigint>>();
    readonly #cursorPrefix: string;
    #syncTail: Promise<void> = Promise.resolve();

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
        access: TopicAccess,
        payload: Uint8Array,
        options: {
            readonly expiresAt?: number;
            readonly collapseKey?: Uint8Array;
        } = {},
    ): Promise<PublishResult> {
        const signer = this.#writeSigner(access);
        return this.publishEvent(createRelayEvent(signer, access.topic, payload, options));
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
        return this.#exclusiveSync(() => this.#sync(waitMilliseconds, signal));
    }

    async #sync(waitMilliseconds: number, signal?: AbortSignal): Promise<SyncResult> {
        const events: ReceivedEvent[] = [];
        const subscriptions = [...this.#subscriptions]
            .filter(([topicId]) => !this.#pending.has(topicId))
            .sort(([left], [right]) => left.localeCompare(right));
        const contexts = await Promise.all(
            subscriptions.map(async ([topicId, access]) => {
                const cursorKey = `${this.#cursorPrefix}${topicId}`;
                const cursor = parseCursor(await this.#store.get(cursorKey));
                return {
                    topicId,
                    cursorKey,
                    cursor,
                    access,
                };
            }),
        );
        const readAll = async (wait: number, readSignal?: AbortSignal) =>
            Promise.all(
                contexts.map(async (context) => ({
                    ...context,
                    page: await this.#transport.readEvents(
                        context.access,
                        context.cursor,
                        DEFAULT_EVENT_PAGE_LIMIT,
                        wait,
                        readSignal,
                    ),
                })),
            );
        let reads = await readAll(0, signal);
        if (
            waitMilliseconds > 0 &&
            contexts.length > 0 &&
            !reads.some(({ cursor, page }) => page.events.length > 0 || page.head > cursor)
        ) {
            const controller = new AbortController();
            const onAbort = (): void => controller.abort(signal?.reason);
            signal?.addEventListener("abort", onAbort, { once: true });
            try {
                const waits = contexts.map((context) =>
                    this.#transport.readEvents(
                        context.access,
                        context.cursor,
                        DEFAULT_EVENT_PAGE_LIMIT,
                        waitMilliseconds,
                        controller.signal,
                    ),
                );
                try {
                    await Promise.race(waits);
                } finally {
                    controller.abort();
                    await Promise.allSettled(waits);
                }
                reads = await readAll(0, signal);
            } finally {
                signal?.removeEventListener("abort", onAbort);
                controller.abort();
            }
        }
        for (const { topicId, cursor, page } of reads) {
            if (page.head < cursor) {
                throw new Error("Relay returned a topic head behind the durable cursor");
            }
            if (page.events.length === 0) {
                if (!page.exhausted) {
                    throw new Error("Relay returned an empty non-exhausted event page");
                }
                continue;
            }
            let previousSequence = cursor;
            for (const retained of page.events) {
                if (
                    retained.seq <= previousSequence ||
                    retained.seq > page.head ||
                    relayTopicId(retained.event.topic) !== topicId ||
                    !verifyRelayEvent(retained.event) ||
                    (retained.event.topic.type !== "read" &&
                        !equalBytes(
                            retained.event.author.signingKey,
                            retained.event.topic.writeKey,
                        ))
                ) {
                    throw new Error("Relay returned an invalid ordered event page");
                }
                previousSequence = retained.seq;
            }
        }
        for (const { topicId, cursorKey, cursor, page } of reads) {
            if (page.events.length === 0) {
                await this.#store.transaction(async (transaction) => {
                    const current = parseCursor(await transaction.get(cursorKey));
                    if (page.head > current) {
                        await transaction.set(cursorKey, cursorBytes(page.head));
                    }
                });
                continue;
            }
            const pending = new Set(page.events.map(({ seq }) => seq));
            this.#pending.set(topicId, pending);
            let previousSequence = cursor;
            for (let index = 0; index < page.events.length; index += 1) {
                const retained = page.events[index]!;
                const isLast = index === page.events.length - 1;
                const target = isLast && page.exhausted ? page.head : retained.seq;
                const expectedCursor = previousSequence;
                events.push({
                    seq: retained.seq,
                    event: retained.event,
                    advanceCursor: async (transaction): Promise<void> => {
                        const current = parseCursor(await transaction.get(cursorKey));
                        if (current !== expectedCursor) {
                            pending.delete(retained.seq);
                            if (pending.size === 0) this.#pending.delete(topicId);
                            throw new Error("Cannot skip an earlier retained relay event");
                        }
                        await transaction.set(cursorKey, cursorBytes(target));
                        pending.delete(retained.seq);
                        if (pending.size === 0) this.#pending.delete(topicId);
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

    #writeSigner(access: TopicAccess): RelaySigningKey {
        if (access.topic.type === "read") {
            return this.#identity;
        }
        const secretKey = access.writeSecretKey;
        if (
            secretKey === undefined ||
            secretKey.length !== 32 ||
            !equalBytes(ed25519.getPublicKey(secretKey), access.topic.writeKey)
        ) {
            throw new Error("Write secret key does not match the topic capability");
        }
        return {
            publicKey: access.topic.writeKey,
            secretKey,
        };
    }

    async #exclusiveSync<Result>(operation: () => Promise<Result>): Promise<Result> {
        let release: (() => void) | undefined;
        const prior = this.#syncTail;
        this.#syncTail = new Promise<void>((resolve) => {
            release = resolve;
        });
        await prior;
        try {
            return await operation();
        } finally {
            release?.();
        }
    }
}
