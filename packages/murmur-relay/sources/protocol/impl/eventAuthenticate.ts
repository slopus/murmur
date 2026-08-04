import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import type { ReadChallenge, RelayTopic, SignedRelayEvent } from "../types.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { relayTopicToJson, signedRelayEventToJson } from "./eventCodec.js";

/** Produce the canonical bytes authenticated by a relay event signature. */
export function relayEventSigningBytes(event: SignedRelayEvent): Uint8Array {
    const encoded = signedRelayEventToJson(event);
    const { signature: _signature, ...unsigned } = encoded;
    return canonicalJson(unsigned);
}

/** Verify one event with strict RFC 8032 Ed25519 semantics. */
export function verifyRelayEventSignature(event: SignedRelayEvent): boolean {
    try {
        return ed25519.verify(
            event.signature,
            relayEventSigningBytes(event),
            event.author.signingKey,
            {
                zip215: false,
            },
        );
    } catch {
        return false;
    }
}

/** Hash the full canonical signed event, including its signature, for idempotency. */
export function relayEventFingerprint(event: SignedRelayEvent): Uint8Array {
    return sha256(canonicalJson(signedRelayEventToJson(event)));
}

/** Derive the stable physical identifier of a typed topic. */
export function relayTopicId(topic: RelayTopic): string {
    return encodeBase64Url(sha256(canonicalJson(relayTopicToJson(topic))));
}

/** Produce exact bytes signed to consume a one-use protected-read challenge. */
export function readProofSigningBytes(
    challenge: ReadChallenge,
    topic: RelayTopic,
    since: bigint,
    limit: number,
    waitMilliseconds: number,
): Uint8Array {
    return canonicalJson({
        challengeId: challenge.id,
        nonce: encodeBase64Url(challenge.nonce),
        topic: relayTopicToJson(topic),
        since: since.toString(),
        limit,
        waitMilliseconds,
    });
}
