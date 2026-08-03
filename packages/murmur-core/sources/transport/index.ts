import type { IdentityKeyPair } from "../crypto/index.js";
import { hashBytes, randomBytes, signBytes, verifyBytes } from "../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    type JsonValue,
} from "../utils/index.js";
import {
    decodeSignedRelayEventWire,
    encodeSignedRelayEventWire,
    signedRelayEventToJson,
} from "./impl/wireCodec.js";
import type { ListOperation, RelayBlob, SignedRelayEvent, SnapshotMutation } from "./types.js";
import { MAX_RELAY_EVENT_PAYLOAD_BYTES } from "./types.js";

export type {
    AppendListOperation,
    DeleteListOperation,
    EventPage,
    ListElement,
    ListOperation,
    ListPage,
    PublishOutcome,
    RelayAuthor,
    RelayBlob,
    RelayFetch,
    RelayStreamHandlers,
    RelayTransport,
    ReplaceListOperation,
    RetainedRelayEvent,
    SignedRelayEvent,
    SnapshotMutation,
    TopicSnapshot,
    TopicState,
} from "./types.js";
export {
    MAX_RELAY_BLOB_BYTES,
    MAX_RELAY_EPHEMERAL_FRAME_BYTES,
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
    RelayBlobIntegrityError,
} from "./types.js";
export { HttpRelayTransport } from "./impl/httpTransport.js";
export {
    decodeEventPageWire,
    decodeListPageWire,
    decodePublishOutcomeWire,
    decodeSignedRelayEventWire,
    decodeTopicStateWire,
    encodeSignedRelayEventWire,
    signedRelayEventToJson,
} from "./impl/wireCodec.js";

export const MAX_RELAY_TOPIC_CHARACTERS = 512;
export const MAX_NESTED_TOPIC_COMPONENT_BYTES = 1_024;
/** Public Murmur relay used when an application explicitly chooses the project default. */
export const DEFAULT_RELAY_URL = "https://murmur.cluster-fluster.com";

/** Derive an opaque child topic which can itself be nested without a depth limit. */
export function deriveNestedTopic(parentTopic: string, component: Uint8Array): string {
    if (
        parentTopic.length === 0 ||
        parentTopic.length > MAX_RELAY_TOPIC_CHARACTERS ||
        component.length === 0 ||
        component.length > MAX_NESTED_TOPIC_COMPONENT_BYTES
    ) {
        throw new Error("Invalid nested topic input");
    }
    return `topic:${encodeBase64Url(
        hashBytes(
            canonicalJsonBytes({
                component: encodeBase64Url(component),
                parent: parentTopic,
                version: 1,
            }),
        ),
    )}`;
}

function signingJson(event: SignedRelayEvent): JsonValue {
    const encoded = signedRelayEventToJson(event);
    return {
        author: encoded.author,
        createdAt: encoded.createdAt,
        id: encoded.id,
        ...(encoded.list === undefined ? {} : { list: encoded.list }),
        payload: encoded.payload,
        ...(encoded.snapshot === undefined ? {} : { snapshot: encoded.snapshot }),
        topic: encoded.topic,
        version: encoded.version,
    } as JsonValue;
}

/** Canonical bytes authenticated by a relay event signature. */
export function relayEventSigningBytes(event: SignedRelayEvent): Uint8Array {
    return canonicalJsonBytes(signingJson(event));
}

/** Create one signed event matching the relay's fixed protocol byte-for-byte. */
export function createRelayEvent(
    author: IdentityKeyPair,
    topic: string,
    payload: Uint8Array,
    mutations: {
        readonly snapshot?: SnapshotMutation;
        readonly list?: readonly ListOperation[];
    } = {},
    now: number = Date.now(),
): SignedRelayEvent {
    if (!/^[A-Za-z0-9_.:-]{1,512}$/.test(topic)) {
        throw new Error("Invalid relay topic");
    }
    if (!(payload instanceof Uint8Array) || payload.length > MAX_RELAY_EVENT_PAYLOAD_BYTES) {
        throw new Error(`Event payload exceeds ${MAX_RELAY_EVENT_PAYLOAD_BYTES} bytes`);
    }
    if (!Number.isSafeInteger(now) || now < 0) {
        throw new Error("Event time must be a non-negative safe integer");
    }
    const unsigned = decodeSignedRelayEventWire(
        encodeSignedRelayEventWire({
            version: 1,
            id: encodeBase64Url(randomBytes(32)),
            topic,
            author: { signingKey: author.signingKey.slice() },
            createdAt: now,
            payload: payload.slice(),
            ...(mutations.snapshot === undefined ? {} : { snapshot: mutations.snapshot }),
            ...(mutations.list === undefined ? {} : { list: mutations.list }),
            signature: new Uint8Array(64),
        }),
    );
    return {
        ...unsigned,
        signature: signBytes(author, relayEventSigningBytes(unsigned)),
    };
}

/** Verify one relay event using the relay's strict Ed25519 profile. */
export function verifyRelayEvent(event: SignedRelayEvent): boolean {
    try {
        decodeSignedRelayEventWire(encodeSignedRelayEventWire(event));
        return (
            /^[A-Za-z0-9_-]{43}$/.test(event.id) &&
            decodeBase64Url(event.id).length === 32 &&
            /^[A-Za-z0-9_.:-]{1,512}$/.test(event.topic) &&
            event.author.signingKey.length === 32 &&
            event.signature.length === 64 &&
            event.payload.length <= MAX_RELAY_EVENT_PAYLOAD_BYTES &&
            verifyBytes(event.author, relayEventSigningBytes(event), event.signature)
        );
    } catch {
        return false;
    }
}

/** Return whether two signed relay events have identical authenticated content. */
export function equalRelayEvents(left: SignedRelayEvent, right: SignedRelayEvent): boolean {
    return (
        equalBytes(relayEventSigningBytes(left), relayEventSigningBytes(right)) &&
        equalBytes(left.signature, right.signature)
    );
}

/** Build a content-addressed ciphertext blob. */
export function createRelayBlob(bytes: Uint8Array): RelayBlob {
    return {
        id: encodeBase64Url(hashBytes(bytes)),
        bytes: bytes.slice(),
    };
}

/** Verify a relay blob's SHA-256 content identifier. */
export function verifyRelayBlob(blob: RelayBlob): boolean {
    return blob.id === encodeBase64Url(hashBytes(blob.bytes));
}
