import { gcm } from "@noble/ciphers/aes";
import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "../../crypto/index.js";
import {
    MAX_RELAY_EVENT_PAYLOAD_BYTES,
    relayTopicToJson,
    type ReadWriteTopic,
    type RelayTopic,
} from "../../transport/index.js";
import {
    canonicalJsonBytes,
    concatBytes,
    equalBytes,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";

const ENVELOPE_VERSION = 1;
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const VERSION_BYTES = 1;
const MAXIMUM_INNER_BYTES = MAX_RELAY_EVENT_PAYLOAD_BYTES - NONCE_BYTES - TAG_BYTES - VERSION_BYTES;
const KEY_INFO = utf8Encode("murmur/group-relay-envelope/key/v1");
const AAD_DOMAIN = "murmur/group-relay-envelope/aad/v1";

function validateGroupTopic(topicSecret: Uint8Array, topic: RelayTopic): ReadWriteTopic {
    if (
        topicSecret.length !== KEY_BYTES ||
        topic.type !== "read-write" ||
        topic.name !== "group-events" ||
        !equalBytes(topic.readKey, topic.writeKey) ||
        !equalBytes(ed25519.getPublicKey(topicSecret), topic.writeKey)
    ) {
        throw new Error("Invalid group relay envelope topic");
    }
    return topic;
}

function envelopeAad(topic: ReadWriteTopic): Uint8Array {
    return canonicalJsonBytes({
        domain: AAD_DOMAIN,
        topic: relayTopicToJson(topic),
    });
}

function envelopeKey(topicSecret: Uint8Array, aad: Uint8Array): Uint8Array {
    return hkdf(sha256, topicSecret, sha256(aad), KEY_INFO, KEY_BYTES);
}

/**
 * Encrypt one MLS Commit or application message for opaque relay retention.
 *
 * The version byte is inside the ciphertext, leaving only a random nonce and
 * AEAD ciphertext visible to the relay.
 */
export function sealGroupRelayPayload(
    topicSecret: Uint8Array,
    topic: RelayTopic,
    inner: Uint8Array,
): Uint8Array {
    const validatedTopic = validateGroupTopic(topicSecret, topic);
    if (!(inner instanceof Uint8Array) || inner.length < 1 || inner.length > MAXIMUM_INNER_BYTES) {
        throw new Error(`Group relay payload must contain 1 to ${MAXIMUM_INNER_BYTES} bytes`);
    }
    const aad = envelopeAad(validatedTopic);
    const key = envelopeKey(topicSecret, aad);
    const nonce = randomBytes(NONCE_BYTES);
    const plaintext = concatBytes(new Uint8Array([ENVELOPE_VERSION]), inner);
    try {
        return concatBytes(nonce, gcm(key, nonce, aad).encrypt(plaintext));
    } finally {
        zeroBytes(aad);
        zeroBytes(key);
        zeroBytes(nonce);
        zeroBytes(plaintext);
    }
}

/** Authenticate and decrypt one strict version-one opaque group relay payload. */
export function openGroupRelayPayload(
    topicSecret: Uint8Array,
    topic: RelayTopic,
    envelope: Uint8Array,
): Uint8Array {
    const validatedTopic = validateGroupTopic(topicSecret, topic);
    if (
        !(envelope instanceof Uint8Array) ||
        envelope.length < NONCE_BYTES + TAG_BYTES + VERSION_BYTES + 1 ||
        envelope.length > MAX_RELAY_EVENT_PAYLOAD_BYTES
    ) {
        throw new Error("Invalid group relay envelope");
    }
    const nonce = envelope.slice(0, NONCE_BYTES);
    const ciphertext = envelope.slice(NONCE_BYTES);
    const aad = envelopeAad(validatedTopic);
    const key = envelopeKey(topicSecret, aad);
    let plaintext: Uint8Array | undefined;
    try {
        plaintext = gcm(key, nonce, aad).decrypt(ciphertext);
        if (
            plaintext.length < VERSION_BYTES + 1 ||
            plaintext[0] !== ENVELOPE_VERSION ||
            plaintext.length - VERSION_BYTES > MAXIMUM_INNER_BYTES
        ) {
            throw new Error("Invalid group relay envelope");
        }
        return plaintext.slice(VERSION_BYTES);
    } catch {
        throw new Error("Invalid group relay envelope");
    } finally {
        zeroBytes(nonce);
        zeroBytes(ciphertext);
        zeroBytes(aad);
        zeroBytes(key);
        plaintext?.fill(0);
    }
}
