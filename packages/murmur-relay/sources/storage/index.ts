import {
    encodeBase64Url,
    equalBytes,
    hashBytes,
    identityId,
    relayEventSignaturePayload,
    type RelayBlob,
    type RelayDelivery,
    type RelayEvent,
    type TopicSubscription,
} from "@slopus/murmur";
import type { PruneResult } from "../relay/types.js";
import type { RelayPublishResult, RelayStore } from "./types.js";

export type { RelayPublishResult, RelayStore } from "./types.js";

interface StoredEvent {
    readonly event: RelayEvent;
    readonly fingerprint: string;
}

interface StoredTopic {
    readonly subscribers: Set<string>;
    lastActivityAt: number;
}

function copyEvent(event: RelayEvent): RelayEvent {
    return {
        version: 1,
        id: event.id,
        topic: event.topic,
        sender: {
            signingKey: event.sender.signingKey.slice(),
            encryptionKey: event.sender.encryptionKey.slice(),
        },
        recipients: [...event.recipients],
        createdAt: event.createdAt,
        payload: event.payload.slice(),
        signature: event.signature.slice(),
    };
}

function copyDelivery(delivery: RelayDelivery): RelayDelivery {
    return {
        deliveryId: delivery.deliveryId,
        event: copyEvent(delivery.event),
    };
}

function fingerprint(event: RelayEvent): string {
    return encodeBase64Url(
        hashBytes(new Uint8Array([...relayEventSignaturePayload(event), ...event.signature])),
    );
}

/** Ephemeral reference store used by local relays and contract tests. */
export class MemoryRelayStore implements RelayStore {
    readonly #topics = new Map<string, StoredTopic>();
    readonly #events = new Map<string, StoredEvent>();
    readonly #queues = new Map<string, RelayDelivery[]>();
    readonly #blobs = new Map<string, RelayBlob>();
    readonly #queueRequests = new Map<string, number>();
    #nextDeliverySequence = 0;

    async addSubscription(subscription: TopicSubscription, observedAt: number): Promise<number> {
        const topic = this.#topics.get(subscription.topic) ?? {
            subscribers: new Set<string>(),
            lastActivityAt: observedAt,
        };
        const subscriberId = identityId(subscription.subscriber);
        const isNewSubscriber = !topic.subscribers.has(subscriberId);
        topic.subscribers.add(subscriberId);
        topic.lastActivityAt = Math.max(topic.lastActivityAt, observedAt);
        this.#topics.set(subscription.topic, topic);
        let replayed = 0;
        if (isNewSubscriber) {
            for (const stored of this.#events.values()) {
                if (
                    stored.event.topic === subscription.topic &&
                    stored.event.recipients.length === 0
                ) {
                    this.#enqueue(subscriberId, stored.event);
                    replayed += 1;
                }
            }
        }
        return replayed;
    }

    async publish(event: RelayEvent, observedAt: number): Promise<RelayPublishResult> {
        const eventFingerprint = fingerprint(event);
        const existing = this.#events.get(event.id);
        if (existing !== undefined) {
            if (existing.fingerprint !== eventFingerprint) {
                throw new Error("Event identifier collision");
            }
            return { disposition: "duplicate", recipients: [] };
        }

        const storedEvent = copyEvent(event);
        this.#events.set(event.id, {
            event: storedEvent,
            fingerprint: eventFingerprint,
        });
        const topic = this.#topics.get(event.topic) ?? {
            subscribers: new Set<string>(),
            lastActivityAt: observedAt,
        };
        topic.lastActivityAt = Math.max(topic.lastActivityAt, observedAt);
        this.#topics.set(event.topic, topic);

        const recipients =
            event.recipients.length > 0 ? event.recipients : [...topic.subscribers].sort();
        for (const recipient of [...new Set(recipients)].sort()) {
            this.#enqueue(recipient, storedEvent);
        }
        return {
            disposition: "inserted",
            recipients: [...new Set(recipients)].sort(),
        };
    }

    async consumeQueueRequest(
        recipientId: string,
        requestId: string,
        expiresAt: number,
        observedAt: number,
    ): Promise<boolean> {
        for (const [key, expiry] of this.#queueRequests) {
            if (expiry <= observedAt) {
                this.#queueRequests.delete(key);
            }
        }
        const key = `${recipientId}/${requestId}`;
        if (this.#queueRequests.has(key)) {
            return false;
        }
        this.#queueRequests.set(key, expiresAt);
        return true;
    }

    async pull(recipientId: string, maximumDeliveries: number): Promise<readonly RelayDelivery[]> {
        return (this.#queues.get(recipientId) ?? []).slice(0, maximumDeliveries).map(copyDelivery);
    }

    async acknowledge(recipientId: string, deliveryId: string): Promise<void> {
        const queue = this.#queues.get(recipientId);
        if (queue === undefined) {
            return;
        }
        this.#queues.set(
            recipientId,
            queue.filter((delivery) => delivery.deliveryId !== deliveryId),
        );
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        const existing = this.#blobs.get(blob.id);
        if (existing !== undefined && !equalBytes(existing.bytes, blob.bytes)) {
            throw new Error("Blob identifier collision");
        }
        this.#blobs.set(blob.id, {
            id: blob.id,
            bytes: blob.bytes.slice(),
        });
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        const blob = this.#blobs.get(id);
        return blob === undefined ? undefined : { id: blob.id, bytes: blob.bytes.slice() };
    }

    async pruneInactiveTopics(olderThan: number): Promise<PruneResult> {
        const expiredTopics = new Set(
            [...this.#topics]
                .filter(([, topic]) => topic.lastActivityAt < olderThan)
                .map(([topic]) => topic),
        );
        for (const topic of expiredTopics) {
            this.#topics.delete(topic);
        }

        let deliveries = 0;
        for (const [recipient, queue] of this.#queues) {
            const retained = queue.filter((delivery) => !expiredTopics.has(delivery.event.topic));
            deliveries += queue.length - retained.length;
            this.#queues.set(recipient, retained);
        }
        for (const [eventId, event] of this.#events) {
            if (expiredTopics.has(event.event.topic)) {
                this.#events.delete(eventId);
            }
        }

        return { topics: expiredTopics.size, deliveries };
    }

    #enqueue(recipient: string, event: RelayEvent): void {
        this.#nextDeliverySequence += 1;
        const delivery: RelayDelivery = {
            deliveryId: this.#nextDeliverySequence.toString(36).padStart(13, "0"),
            event,
        };
        const queue = this.#queues.get(recipient) ?? [];
        queue.push(delivery);
        this.#queues.set(recipient, queue);
    }
}
