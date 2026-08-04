import { ed25519 } from "@noble/curves/ed25519";
import type { IdentityKeyPair, IdentityPublicKey } from "../../crypto/index.js";
import { randomBytes } from "../../crypto/index.js";
import { FriendChannel } from "../../identity/index.js";
import {
    createRelayEvent,
    type ReadTopic,
    type ReadWriteTopic,
    type SignedRelayEvent,
    type TopicAccess,
} from "../../transport/index.js";
import { decodeBase64Url, encodeBase64Url, equalBytes, zeroBytes } from "../../utils/index.js";

const INBOX_PREFIX = "murmur-inbox-v1.";
const RESPONSE_PREFIX = "murmur-response-v1.";

/** Derive the intentionally public, identity-linked request inbox. */
export function inboxAccess(identity: IdentityKeyPair): TopicAccess {
    const topic: ReadTopic = {
        type: "read",
        name: "friend-requests",
        readKey: identity.publicKey.slice(),
    };
    return {
        topic,
        readSecretKey: identity.secretKey.slice(),
    };
}

/** Encode the request destination retained by the semantic friend outbox. */
export function inboxAddress(identity: IdentityPublicKey): string {
    if (identity.publicKey.length !== 32) {
        throw new Error("Invalid inbox identity key");
    }
    return `${INBOX_PREFIX}${encodeBase64Url(identity.publicKey)}`;
}

/** Strictly decode one request destination into its public Read Topic. */
export function parseInboxAddress(address: string): ReadTopic {
    if (!address.startsWith(INBOX_PREFIX) || address.length !== INBOX_PREFIX.length + 43) {
        throw new Error("Invalid friend inbox address");
    }
    const readKey = decodeBase64Url(address.slice(INBOX_PREFIX.length));
    if (readKey.length !== 32) {
        throw new Error("Invalid friend inbox address");
    }
    return { type: "read", name: "friend-requests", readKey };
}

/**
 * Generate a protected one-request response topic.
 *
 * The opaque address contains its random read capability because it is itself
 * carried only inside the recipient-confidential friend request.
 */
export function createResponseAddress(): string {
    const secret = randomBytes(32);
    try {
        return `${RESPONSE_PREFIX}${encodeBase64Url(secret)}`;
    } finally {
        zeroBytes(secret);
    }
}

/** Strictly restore a response topic and its read capability. */
export function parseResponseAddress(address: string): TopicAccess {
    if (!address.startsWith(RESPONSE_PREFIX) || address.length !== RESPONSE_PREFIX.length + 43) {
        throw new Error("Invalid friend response address");
    }
    const secret = decodeBase64Url(address.slice(RESPONSE_PREFIX.length));
    try {
        if (secret.length !== 32) {
            throw new Error("Invalid friend response address");
        }
        const readKey = ed25519.getPublicKey(secret);
        return {
            topic: { type: "read", name: "friend-responses", readKey },
            readSecretKey: secret.slice(),
        };
    } finally {
        zeroBytes(secret);
    }
}

/** Derive the stable encrypted control topic shared by two active friends. */
export function friendControlAccess(channel: FriendChannel): TopicAccess {
    const secret = channel.exportTopicSecretKey();
    try {
        const topic: ReadWriteTopic = {
            type: "read-write",
            name: "control",
            readKey: channel.topicPublicKey,
            writeKey: channel.topicPublicKey,
        };
        return {
            topic,
            readSecretKey: secret.slice(),
            writeSecretKey: secret.slice(),
        };
    } finally {
        zeroBytes(secret);
    }
}

/** Restore one stable random group topic capability. */
export function groupAccess(topicSecret: Uint8Array): TopicAccess {
    if (topicSecret.length !== 32) {
        throw new Error("Invalid group topic secret");
    }
    const key = ed25519.getPublicKey(topicSecret);
    const topic: ReadWriteTopic = {
        type: "read-write",
        name: "group-events",
        readKey: key,
        writeKey: key,
    };
    return {
        topic,
        readSecretKey: topicSecret.slice(),
        writeSecretKey: topicSecret.slice(),
    };
}

/** Create a request/response relay event under a fresh unlinkable author. */
export function createUnlinkableEvent(topic: ReadTopic, payload: Uint8Array): SignedRelayEvent {
    const secretKey = randomBytes(32);
    try {
        return createRelayEvent(
            { publicKey: ed25519.getPublicKey(secretKey), secretKey },
            topic,
            payload,
        );
    } finally {
        zeroBytes(secretKey);
    }
}

/** Create an event signed by a shared read/write topic capability. */
export function createCapabilityEvent(
    access: TopicAccess,
    payload: Uint8Array,
    options: { readonly expiresAt?: number; readonly createdAt?: number } = {},
): SignedRelayEvent {
    if (
        access.topic.type !== "read-write" ||
        access.writeSecretKey === undefined ||
        access.writeSecretKey.length !== 32 ||
        !equalBytes(ed25519.getPublicKey(access.writeSecretKey), access.topic.writeKey)
    ) {
        throw new Error("Invalid shared topic write capability");
    }
    return createRelayEvent(
        {
            publicKey: access.topic.writeKey,
            secretKey: access.writeSecretKey,
        },
        access.topic,
        payload,
        options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt },
        options.createdAt,
    );
}
