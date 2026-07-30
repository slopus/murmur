import type { IdentityKeyPair, IdentityPublicKeys } from "../crypto/index.js";
import { hashBytes } from "../crypto/index.js";
import { identityId } from "../identity/index.js";
import type { MurmurStore } from "../storage/index.js";
import {
    createQueueAcknowledgeRequest,
    createQueueReadRequest,
    createRelayBlob,
    createRelayEvent,
    createTopicSubscription,
    relayEventSignaturePayload,
    verifyRelayBlob,
    verifyRelayEvent,
    type RelayBlob,
    type RelayDelivery,
    type RelayEvent,
    type RelayTransport,
} from "../transport/index.js";
import { encodeBase64Url, equalBytes } from "../utils/index.js";
import { decodeOutboundRecord, encodeOutboundRecord } from "./impl/eventCodec.js";
import type { PublishResult, ReceivedEvent } from "./types.js";

export type { PublishResult, ReceivedEvent } from "./types.js";

const DEFAULT_OUTBOUND_HISTORY = 256;

interface DeliveryOrigin {
    readonly transport: RelayTransport;
    readonly deliveryId: string;
}

interface InFlightEvent {
    readonly event: RelayEvent;
    readonly origins: Map<string, DeliveryOrigin>;
}

function isAborted(signal: AbortSignal | undefined): boolean {
    return signal?.aborted === true;
}

/** Transport-agnostic Murmur event client. */
export class MurmurClient {
    readonly #identity: IdentityKeyPair;
    readonly #recipientId: string;
    readonly #store: MurmurStore;
    readonly #transports: readonly RelayTransport[];
    readonly #inFlight = new Map<string, InFlightEvent>();
    readonly #outboundHistoryLimit: number;
    readonly #acknowledgedPrefix: string;
    readonly #outboundPrefix: string;

    constructor(options: {
        identity: IdentityKeyPair;
        store: MurmurStore;
        transports: readonly RelayTransport[];
        outboundHistoryLimit?: number;
    }) {
        if (options.transports.length === 0) {
            throw new Error("At least one transport is required");
        }
        const transportIds = new Set(options.transports.map((transport) => transport.id));
        if (transportIds.size !== options.transports.length) {
            throw new Error("Transport identifiers must be unique");
        }
        const outboundHistoryLimit = options.outboundHistoryLimit ?? DEFAULT_OUTBOUND_HISTORY;
        if (!Number.isSafeInteger(outboundHistoryLimit) || outboundHistoryLimit < 1) {
            throw new Error("Outbound history limit must be a positive safe integer");
        }

        this.#identity = options.identity;
        this.#recipientId = identityId(options.identity);
        this.#store = options.store;
        this.#transports = [...options.transports];
        this.#outboundHistoryLimit = outboundHistoryLimit;
        this.#acknowledgedPrefix = `client/${this.#recipientId}/acknowledged/`;
        this.#outboundPrefix = `client/${this.#recipientId}/outbound/`;
    }

    /** Subscribe this identity to a topic on every configured transport. */
    async subscribe(topic: string): Promise<void> {
        const subscription = createTopicSubscription(this.#identity, topic);
        const results = await Promise.allSettled(
            this.#transports.map(async (transport) => transport.subscribe(subscription)),
        );
        if (!results.some((result) => result.status === "fulfilled")) {
            throw new AggregateError(
                results
                    .filter(
                        (result): result is PromiseRejectedResult => result.status === "rejected",
                    )
                    .map((result) => result.reason),
                "Every transport rejected the subscription",
            );
        }
    }

    /** Publish opaque bytes to subscribers or an explicit recipient list. */
    async publish(
        topic: string,
        payload: Uint8Array,
        recipients: readonly IdentityPublicKeys[] = [],
    ): Promise<PublishResult> {
        const event = createRelayEvent(this.#identity, topic, payload, recipients);
        const key = `${this.#outboundPrefix}${event.createdAt.toString().padStart(16, "0")}/${event.id}`;
        await this.#store.set(key, encodeOutboundRecord(event, []));
        const result = await this.#publishRecord(key, event, []);
        await this.#pruneOutboundHistory();
        return result;
    }

    /** Retry retained events on transports which have not accepted them. */
    async retryOutbound(): Promise<readonly PublishResult[]> {
        const records = await this.#store.list(this.#outboundPrefix);
        const results: PublishResult[] = [];
        for (const [key, value] of [...records].sort(([left], [right]) =>
            left.localeCompare(right),
        )) {
            const record = decodeOutboundRecord(value);
            results.push(await this.#publishRecord(key, record.event, record.publishedRelayIds));
        }
        return results;
    }

    async #publishRecord(
        key: string,
        event: RelayEvent,
        previouslyPublishedRelayIds: readonly string[],
    ): Promise<PublishResult> {
        const published = new Set(previouslyPublishedRelayIds);
        const pending = this.#transports.filter((transport) => !published.has(transport.id));
        const attempts = await Promise.allSettled(
            pending.map(async (transport) => {
                await transport.publish(event);
                return transport.id;
            }),
        );
        const failedRelayIds: string[] = [];
        for (let index = 0; index < attempts.length; index += 1) {
            const attempt = attempts[index];
            const transport = pending[index];
            if (attempt?.status === "fulfilled") {
                published.add(attempt.value);
            } else if (transport !== undefined) {
                failedRelayIds.push(transport.id);
            }
        }
        await this.#store.set(key, encodeOutboundRecord(event, [...published]));

        if (published.size === 0) {
            throw new Error("Every transport rejected the event");
        }
        return {
            event,
            publishedRelayIds: [...published].sort(),
            failedRelayIds: failedRelayIds.sort(),
        };
    }

    /** Pull, authenticate, merge, and order one batch from every relay. */
    async sync(
        waitMilliseconds: number = 0,
        signal?: AbortSignal,
    ): Promise<readonly ReceivedEvent[]> {
        const readRequest = createQueueReadRequest(this.#identity);
        const pulls = await Promise.allSettled(
            this.#transports.map(async (transport) => ({
                transport,
                deliveries: await transport.pull(readRequest, waitMilliseconds, signal),
            })),
        );
        if (!pulls.some((pull) => pull.status === "fulfilled")) {
            throw new Error("Every transport failed while pulling events");
        }

        const received: ReceivedEvent[] = [];
        for (const pull of pulls) {
            if (pull.status !== "fulfilled") {
                continue;
            }
            for (const delivery of pull.value.deliveries) {
                if (
                    !verifyRelayEvent(delivery.event) ||
                    (delivery.event.recipients.length > 0 &&
                        !delivery.event.recipients.includes(this.#recipientId))
                ) {
                    await Promise.allSettled([
                        this.#acknowledge(pull.value.transport, delivery.deliveryId),
                    ]);
                    continue;
                }
                const item = await this.#acceptDelivery(pull.value.transport, delivery);
                if (item !== undefined) {
                    received.push(item);
                }
            }
        }
        return received.sort(
            (left, right) =>
                left.event.createdAt - right.event.createdAt ||
                left.event.id.localeCompare(right.event.id),
        );
    }

    /**
     * Yield near-realtime batches using transport long-polling.
     *
     * Breaking the loop does not acknowledge the current event.
     */
    async *events(
        signal?: AbortSignal,
        waitMilliseconds: number = 25_000,
    ): AsyncIterable<ReceivedEvent> {
        for (;;) {
            if (isAborted(signal)) {
                return;
            }
            let batch: readonly ReceivedEvent[];
            try {
                batch = await this.sync(waitMilliseconds, signal);
            } catch (error: unknown) {
                if (isAborted(signal)) {
                    return;
                }
                throw error;
            }
            for (const event of batch) {
                if (isAborted(signal)) {
                    return;
                }
                yield event;
            }
        }
    }

    /** Upload ciphertext to all reachable relays and return its content ID. */
    async putBlob(ciphertext: Uint8Array): Promise<RelayBlob> {
        const blob = createRelayBlob(ciphertext);
        const attempts = await Promise.allSettled(
            this.#transports.map(async (transport) => transport.putBlob(blob)),
        );
        if (!attempts.some((attempt) => attempt.status === "fulfilled")) {
            throw new Error("Every transport rejected the blob");
        }
        return blob;
    }

    /** Download a ciphertext blob from the first relay with a valid copy. */
    async getBlob(id: string): Promise<RelayBlob | undefined> {
        for (const transport of this.#transports) {
            try {
                const blob = await transport.getBlob(id);
                if (blob !== undefined) {
                    if (!verifyRelayBlob(blob)) {
                        throw new Error(`Relay ${transport.id} returned a corrupt blob`);
                    }
                    return blob;
                }
            } catch {
                // Try the next independently configured transport.
            }
        }
        return undefined;
    }

    async #acceptDelivery(
        transport: RelayTransport,
        delivery: RelayDelivery,
    ): Promise<ReceivedEvent | undefined> {
        const fingerprintBytes = hashBytes(
            new Uint8Array([
                ...relayEventSignaturePayload(delivery.event),
                ...delivery.event.signature,
            ]),
        );
        const fingerprint = encodeBase64Url(fingerprintBytes);
        const deduplicationId = `${delivery.event.id}/${fingerprint}`;
        const acknowledgedKey = `${this.#acknowledgedPrefix}${deduplicationId}`;
        const acknowledgedFingerprint = await this.#store.get(acknowledgedKey);
        if (
            acknowledgedFingerprint !== undefined &&
            equalBytes(acknowledgedFingerprint, fingerprintBytes)
        ) {
            await this.#acknowledge(transport, delivery.deliveryId);
            return undefined;
        }

        const existing = this.#inFlight.get(deduplicationId);
        if (existing !== undefined) {
            existing.origins.set(transport.id, {
                transport,
                deliveryId: delivery.deliveryId,
            });
            return undefined;
        }

        const inFlight: InFlightEvent = {
            event: delivery.event,
            origins: new Map([
                [
                    transport.id,
                    {
                        transport,
                        deliveryId: delivery.deliveryId,
                    },
                ],
            ]),
        };
        this.#inFlight.set(deduplicationId, inFlight);

        return {
            event: delivery.event,
            acknowledge: async (): Promise<void> => {
                const current = this.#inFlight.get(deduplicationId) ?? inFlight;
                await this.#store.set(acknowledgedKey, fingerprintBytes);
                this.#inFlight.delete(deduplicationId);
                await Promise.allSettled(
                    [...current.origins.values()].map(async (origin) =>
                        this.#acknowledge(origin.transport, origin.deliveryId),
                    ),
                );
            },
        };
    }

    async #acknowledge(transport: RelayTransport, deliveryId: string): Promise<void> {
        await transport.acknowledge(createQueueAcknowledgeRequest(this.#identity, deliveryId));
    }

    async #pruneOutboundHistory(): Promise<void> {
        const records = [...(await this.#store.list(this.#outboundPrefix)).keys()].sort();
        const excess = records.length - this.#outboundHistoryLimit;
        if (excess <= 0) {
            return;
        }
        await this.#store.transaction(async (transaction) => {
            for (const key of records.slice(0, excess)) {
                await transaction.delete(key);
            }
        });
    }
}
