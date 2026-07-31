import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import type { SignedRelayEvent } from "../types.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { signedRelayEventToJson } from "./eventCodec.js";

function signingJson(event: SignedRelayEvent): Record<string, unknown> {
    const encoded = signedRelayEventToJson(event);
    const unsigned: Record<string, unknown> = {
        version: encoded.version,
        id: encoded.id,
        topic: encoded.topic,
        author: encoded.author,
        createdAt: encoded.createdAt,
        payload: encoded.payload,
    };
    if (encoded.snapshot !== undefined) {
        unsigned.snapshot = encoded.snapshot;
    }
    if (encoded.list !== undefined) {
        unsigned.list = encoded.list;
    }
    return unsigned;
}

/** Produce the canonical bytes authenticated by a relay event signature. */
export function relayEventSigningBytes(event: SignedRelayEvent): Uint8Array {
    return canonicalJson(signingJson(event));
}

/** Verify one event with strict RFC 8032 Ed25519 semantics. */
export function verifyRelayEventSignature(event: SignedRelayEvent): boolean {
    try {
        return ed25519.verify(
            event.signature,
            relayEventSigningBytes(event),
            event.author.signingKey,
            { zip215: false },
        );
    } catch {
        return false;
    }
}

/** Hash the canonical signature preimage for topic-local content idempotency. */
export function relayEventFingerprint(event: SignedRelayEvent): Uint8Array {
    return sha256(relayEventSigningBytes(event));
}
