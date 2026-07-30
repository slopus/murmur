import type { MurmurClient, PublishResult, ReceivedEvent } from "@murmur/core";
import type { OpenedMlsApplicationMessage } from "../privateMessage/index.js";

/** Minimal client surface used by a group channel. */
export type MlsGroupMurmurClient = Pick<MurmurClient, "publish" | "subscribe">;

/** Successfully authenticated MLS application delivery awaiting manual ack. */
export interface OpenedMlsGroupDelivery {
    readonly status: "opened";
    readonly message: OpenedMlsApplicationMessage;
    readonly event: ReceivedEvent["event"];
    acknowledge(): Promise<void>;
}

/** Current-epoch delivery which could not yet be opened, also awaiting manual ack. */
export interface DeferredMlsGroupDelivery {
    readonly status: "deferred";
    readonly error: Error;
    readonly event: ReceivedEvent["event"];
    acknowledge(): Promise<void>;
}

/** Result of dispatching one transport delivery to a current-epoch channel. */
export type MlsGroupDelivery = OpenedMlsGroupDelivery | DeferredMlsGroupDelivery;

/** Return type retained for the send method's public contract. */
export type MlsGroupPublishResult = PublishResult;
