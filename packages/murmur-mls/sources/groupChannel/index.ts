import { encodeBase64Url, hashBytes, type ReceivedEvent } from "@murmur/core";
import { MlsEpochState } from "../epoch/index.js";
import type { MlsGroupDelivery, MlsGroupMurmurClient, MlsGroupPublishResult } from "./types.js";

export type {
    DeferredMlsGroupDelivery,
    MlsGroupDelivery,
    MlsGroupMurmurClient,
    MlsGroupPublishResult,
    OpenedMlsGroupDelivery,
} from "./types.js";

/** Stable opaque relay topic for one MLS group identifier. */
export function mlsGroupTopic(groupId: Uint8Array): string {
    if (groupId.length === 0 || groupId.length > 255) {
        throw new Error("Invalid MLS group identifier");
    }
    return `mls:${encodeBase64Url(hashBytes(groupId))}`;
}

/**
 * Relay adapter for one current MLS epoch.
 *
 * The application calls `MurmurClient.sync()` once and dispatches each
 * `ReceivedEvent` to its channels. This preserves the client's cross-group
 * in-flight deduplication and explicit acknowledgement semantics.
 */
export class MlsGroupChannel {
    readonly #epoch: MlsEpochState;
    readonly #topic: string;

    constructor(epoch: MlsEpochState) {
        this.#epoch = epoch;
        this.#topic = mlsGroupTopic(epoch.context.groupId);
    }

    /** Opaque relay topic shared by every epoch of this group. */
    get topic(): string {
        return this.#topic;
    }

    /** Subscribe the local Murmur identity to the group's relay topic. */
    async subscribe(client: MlsGroupMurmurClient): Promise<void> {
        await client.subscribe(this.#topic);
    }

    /** Encrypt and publish current-epoch application content. */
    async send(
        client: MlsGroupMurmurClient,
        applicationData: Uint8Array,
        authenticatedData: Uint8Array = new Uint8Array(),
        paddingBytes: number = 0,
    ): Promise<MlsGroupPublishResult> {
        return client.publish(
            this.#topic,
            this.#epoch.seal(applicationData, authenticatedData, paddingBytes),
        );
    }

    /**
     * Dispatch one already authenticated relay delivery.
     *
     * `undefined` means another channel owns the topic. A deferred result is
     * deliberately not auto-acknowledged: it may be a valid future-epoch event.
     */
    handle(received: ReceivedEvent): MlsGroupDelivery | undefined {
        if (received.event.topic !== this.#topic) {
            return undefined;
        }
        try {
            return {
                status: "opened",
                message: this.#epoch.open(received.event.payload),
                event: received.event,
                acknowledge: received.acknowledge,
            };
        } catch (error: unknown) {
            return {
                status: "deferred",
                error: error instanceof Error ? error : new Error("MLS group open failed"),
                event: received.event,
                acknowledge: received.acknowledge,
            };
        }
    }

    /** Destroy the owned current epoch. */
    destroy(): void {
        this.#epoch.destroy();
    }
}
