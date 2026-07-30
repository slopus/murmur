import type {
    QueueAcknowledgeRequest,
    QueueReadRequest,
    RelayBlob,
    RelayDelivery,
    RelayEvent,
    RelayTransport,
    TopicSubscription,
} from "@slopus/murmur";
import type { RelayService } from "../relay/index.js";

/** In-process transport over a relay service. */
export class EmbeddedRelayTransport implements RelayTransport {
    constructor(
        readonly id: string,
        readonly service: RelayService,
    ) {}

    async publish(event: RelayEvent): Promise<void> {
        await this.service.publish(event);
    }

    async subscribe(subscription: TopicSubscription): Promise<void> {
        await this.service.subscribe(subscription);
    }

    async pull(
        request: QueueReadRequest,
        waitMilliseconds?: number,
        signal?: AbortSignal,
    ): Promise<readonly RelayDelivery[]> {
        return this.service.pull(request, waitMilliseconds, signal);
    }

    async acknowledge(request: QueueAcknowledgeRequest): Promise<void> {
        await this.service.acknowledge(request);
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        await this.service.putBlob(blob);
    }

    async getBlob(id: string): Promise<RelayBlob | undefined> {
        return this.service.getBlob(id);
    }
}
