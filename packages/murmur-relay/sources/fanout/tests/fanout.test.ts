import { describe, expect, test } from "vitest";
import { deliveryFingerprint, type SignedDelivery } from "../../protocol/index.js";
import {
    eventId,
    identity,
    recipients,
    secret,
    signedDelivery,
} from "../../protocol/tests/helpers.js";
import type { RelayStorePublishOutcome } from "../../storage/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import {
    DurableFanoutCoordinator,
    type DurableFanoutStore,
    type FanoutRetryScheduler,
    type FanoutTarget,
    type PendingFanoutManifest,
} from "../index.js";

const NOW = 10_000;

interface MutableManifest {
    readonly eventId: string;
    readonly delivery: SignedDelivery;
    readonly admissionPrincipal: string;
    pendingRecipients: Uint8Array[];
}

class MemoryFanoutStore implements DurableFanoutStore {
    readonly manifests: MutableManifest[] = [];
    readonly fingerprints = new Map<string, { eventId: string; fingerprint: string }>();

    async reserve(
        delivery: SignedDelivery,
        admissionPrincipal: string,
        _now: number,
    ): Promise<RelayStorePublishOutcome> {
        const key = `${encodeBase64Url(delivery.sender)}:${delivery.id}`;
        const fingerprint = encodeBase64Url(deliveryFingerprint(delivery));
        const existing = this.fingerprints.get(key);
        if (existing !== undefined) {
            if (existing.fingerprint !== fingerprint) throw new Error("collision");
            return {
                eventId: existing.eventId,
                duplicate: true,
                recipients: delivery.recipients,
            };
        }
        const assigned = eventId(this.manifests.length + 1);
        this.fingerprints.set(key, { eventId: assigned, fingerprint });
        this.manifests.push({
            eventId: assigned,
            delivery,
            admissionPrincipal,
            pendingRecipients: delivery.recipients.map((value) => value.slice()),
        });
        return { eventId: assigned, duplicate: false, recipients: delivery.recipients };
    }

    async oldestPending(now: number): Promise<PendingFanoutManifest | undefined> {
        const manifest = this.manifests.find(
            (candidate) =>
                candidate.delivery.expiresAt > now && candidate.pendingRecipients.length > 0,
        );
        return manifest;
    }

    async markDelivered(
        sender: Uint8Array,
        deliveryId: string,
        recipient: Uint8Array,
    ): Promise<void> {
        const manifest = this.manifests.find(
            (candidate) =>
                candidate.delivery.id === deliveryId &&
                encodeBase64Url(candidate.delivery.sender) === encodeBase64Url(sender),
        );
        if (manifest === undefined) return;
        const encoded = encodeBase64Url(recipient);
        manifest.pendingRecipients = manifest.pendingRecipients.filter(
            (value) => encodeBase64Url(value) !== encoded,
        );
    }

    async pruneExpired(): Promise<number> {
        return 0;
    }
}

describe("durable ordered fanout", () => {
    test("persists before acceptance and retries partial insertion before later manifests", async () => {
        const alice = secret(1);
        const bob = identity(secret(2));
        const carol = identity(secret(3));
        const first = signedDelivery(alice, recipients(bob, carol), {
            id: 1,
            now: NOW,
            expiresAt: NOW + 60_000,
        });
        const second = signedDelivery(alice, recipients(bob), {
            id: 2,
            now: NOW,
            expiresAt: NOW + 60_000,
        });
        const store = new MemoryFanoutStore();
        const scheduled: number[] = [];
        const scheduler: FanoutRetryScheduler = {
            schedule: async (at) => {
                scheduled.push(at);
            },
        };
        const inserted: string[] = [];
        let failBobOnce = true;
        const target: FanoutTarget = {
            insert: async (recipient, assigned, delivery) => {
                const name = encodeBase64Url(recipient) === encodeBase64Url(bob) ? "bob" : "carol";
                inserted.push(`${assigned}:${name}`);
                if (delivery.id === first.id && name === "bob" && failBobOnce) {
                    failBobOnce = false;
                    throw new Error("temporary target failure");
                }
            },
        };
        const coordinator = new DurableFanoutCoordinator(store, target, scheduler, {
            now: () => NOW,
        });

        await expect(coordinator.publish(first, "account-1")).resolves.toEqual({
            eventId: eventId(1),
            duplicate: false,
        });
        await coordinator.publish(second, "account-1");
        expect(store.manifests).toHaveLength(2);
        expect(scheduled).toEqual([NOW, NOW]);

        await expect(coordinator.retry()).resolves.toEqual({
            completedManifests: 0,
            pending: true,
        });
        expect(inserted).toEqual([`${eventId(1)}:bob`, `${eventId(1)}:carol`]);
        expect(store.manifests[1]!.pendingRecipients).toHaveLength(1);

        await expect(coordinator.retry()).resolves.toEqual({
            completedManifests: 2,
            pending: false,
        });
        expect(inserted.slice(2)).toEqual([`${eventId(1)}:bob`, `${eventId(2)}:bob`]);
        expect(store.manifests.every((value) => value.pendingRecipients.length === 0)).toBe(true);
    });
});
