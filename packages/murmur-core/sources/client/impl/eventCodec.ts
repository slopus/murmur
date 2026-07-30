import {
    deserializePublicIdentity,
    serializePublicIdentity,
    type SerializedPublicIdentity,
} from "../../identity/index.js";
import type { RelayEvent } from "../../transport/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

interface SerializedRelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly sender: SerializedPublicIdentity;
    readonly recipients: readonly string[];
    readonly createdAt: number;
    readonly payload: string;
    readonly signature: string;
}

interface OutboundRecord {
    readonly event: SerializedRelayEvent;
    readonly publishedRelayIds: readonly string[];
}

function serializeEvent(event: RelayEvent): SerializedRelayEvent {
    return {
        version: 1,
        id: event.id,
        topic: event.topic,
        sender: serializePublicIdentity(event.sender),
        recipients: [...event.recipients],
        createdAt: event.createdAt,
        payload: encodeBase64Url(event.payload),
        signature: encodeBase64Url(event.signature),
    };
}

function deserializeEvent(event: SerializedRelayEvent): RelayEvent {
    return {
        version: 1,
        id: event.id,
        topic: event.topic,
        sender: deserializePublicIdentity(event.sender),
        recipients: [...event.recipients],
        createdAt: event.createdAt,
        payload: decodeBase64Url(event.payload),
        signature: decodeBase64Url(event.signature),
    };
}

/** Persist a relay event plus the relays which already accepted it. */
export function encodeOutboundRecord(
    event: RelayEvent,
    publishedRelayIds: readonly string[],
): Uint8Array {
    const value: OutboundRecord = {
        event: serializeEvent(event),
        publishedRelayIds: [...publishedRelayIds].sort(),
    };
    return utf8Encode(JSON.stringify(value));
}

/** Decode a trusted record previously created by the client. */
export function decodeOutboundRecord(bytes: Uint8Array): {
    event: RelayEvent;
    publishedRelayIds: readonly string[];
} {
    const value = JSON.parse(utf8Decode(bytes)) as OutboundRecord;
    return {
        event: deserializeEvent(value.event),
        publishedRelayIds: [...value.publishedRelayIds],
    };
}
