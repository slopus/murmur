import { ed25519 } from "@noble/curves/ed25519";
import { hashBytes, randomBytes, verifyBytes } from "../crypto/index.js";
import { canonicalJsonBytes, encodeBase64Url, equalBytes, type JsonValue } from "../utils/index.js";
import {
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    relayTopicToJson,
    signedRelayEventToJson,
} from "./impl/wireCodec.js";
import type { RelaySigningKey, RelayTopic, SignedRelayEvent } from "./types.js";

export type {
    EventPage,
    PublishOutcome,
    ReadTopic,
    ReadWriteTopic,
    RelayFetch,
    RelaySigningKey,
    RelayTopic,
    RelayTransport,
    RetainedRelayEvent,
    SignedRelayEvent,
    TopicAccess,
    WriteTopic,
} from "./types.js";
export { HttpRelayTransport } from "./impl/httpTransport.js";
export {
    decodeEventPageWire,
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    relayTopicToJson,
    signedRelayEventToJson,
    validateRelayTopic,
} from "./impl/wireCodec.js";

/** Maximum event payload accepted by the default relay profile. */
export const MAX_RELAY_EVENT_PAYLOAD_BYTES = 1024 * 1024;

/** Derive the stable physical identifier of a typed topic. */
export function relayTopicId(topic: RelayTopic): string {
    return encodeBase64Url(hashBytes(canonicalJsonBytes(relayTopicToJson(topic))));
}

/** Canonical bytes authenticated by a relay event signature. */
export function relayEventSigningBytes(event: SignedRelayEvent): Uint8Array {
    const encoded = signedRelayEventToJson(event);
    const { signature: _signature, ...unsigned } = encoded;
    return canonicalJsonBytes(unsigned);
}

/** Create one signed durable event. */
export function createRelayEvent(
    author: RelaySigningKey,
    topic: RelayTopic,
    payload: Uint8Array,
    options: {
        readonly expiresAt?: number;
        readonly collapseKey?: Uint8Array;
    } = {},
    now: number = Date.now(),
): SignedRelayEvent {
    if (!(payload instanceof Uint8Array) || payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
        throw new Error(`Event payload exceeds ${MAX_RELAY_EVENT_PAYLOAD_BYTES} bytes`);
    }
    const unsigned = decodeSignedRelayEventWire(
        encodeSignedRelayEventWire({
            version: 1,
            id: encodeBase64Url(randomBytes(32)),
            topic,
            author: { signingKey: author.signingKey.slice() },
            createdAt: now,
            ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
            ...(options.collapseKey === undefined
                ? {}
                : { collapseKey: options.collapseKey.slice() }),
            payload: payload.slice(),
            signature: new Uint8Array(64),
        }),
    );
    if (
        author.signingKey.length !== 32 ||
        author.signingSecretKey.length !== 32 ||
        !equalBytes(ed25519.getPublicKey(author.signingSecretKey), author.signingKey)
    ) {
        throw new Error("Invalid relay signing key");
    }
    return {
        ...unsigned,
        signature: ed25519.sign(relayEventSigningBytes(unsigned), author.signingSecretKey),
    };
}

/** Verify an event using strict Ed25519 and exact wire validation. */
export function verifyRelayEvent(event: SignedRelayEvent): boolean {
    try {
        decodeSignedRelayEventWire(encodeSignedRelayEventWire(event));
        return verifyBytes(event.author, relayEventSigningBytes(event), event.signature);
    } catch {
        return false;
    }
}

/** Return whether two events have identical authenticated content. */
export function equalRelayEvents(left: SignedRelayEvent, right: SignedRelayEvent): boolean {
    return equalBytes(
        canonicalJsonBytes(signedRelayEventToJson(left) as unknown as JsonValue),
        canonicalJsonBytes(signedRelayEventToJson(right) as unknown as JsonValue),
    );
}
