import {
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    type SignedRelayEvent,
} from "../../transport/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

interface OutboundRecord {
    readonly event: string;
    readonly publishedRelayIds: readonly string[];
}

/** Persist a relay event plus the relays which already accepted it. */
export function encodeOutboundRecord(
    event: SignedRelayEvent,
    publishedRelayIds: readonly string[],
): Uint8Array {
    const value: OutboundRecord = {
        event: encodeBase64Url(encodeSignedRelayEventWire(event)),
        publishedRelayIds: [...publishedRelayIds].sort(),
    };
    return utf8Encode(JSON.stringify(value));
}

/** Decode a trusted record previously created by the client. */
export function decodeOutboundRecord(bytes: Uint8Array): {
    event: SignedRelayEvent;
    publishedRelayIds: readonly string[];
} {
    const value = JSON.parse(utf8Decode(bytes)) as OutboundRecord;
    return {
        event: decodeSignedRelayEventWire(decodeBase64Url(value.event)),
        publishedRelayIds: [...value.publishedRelayIds],
    };
}
