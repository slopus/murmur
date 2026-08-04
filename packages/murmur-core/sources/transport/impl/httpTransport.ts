import { ed25519 } from "@noble/curves/ed25519";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
} from "../../utils/index.js";
import type {
    EventPage,
    PublishOutcome,
    RelayFetch,
    RelayTopic,
    RelayTransport,
    SignedRelayEvent,
    TopicAccess,
} from "../types.js";
import { decodeEventPageWire, encodeSignedRelayEventWire, relayTopicToJson } from "./wireCodec.js";

interface Challenge {
    readonly id: string;
    readonly nonce: Uint8Array;
    readonly expiresAt: number;
}

function body(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer as ArrayBuffer;
}

async function responseBytes(response: Response, maximumBytes: number): Promise<Uint8Array> {
    const declared = response.headers.get("content-length");
    if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) {
        throw new Error("Relay response is too large");
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader !== undefined) {
        try {
            for (;;) {
                const result = await reader.read();
                if (result.done) break;
                size += result.value.length;
                if (size > maximumBytes || chunks.length >= 65_536) {
                    await reader.cancel().catch(() => undefined);
                    throw new Error("Relay response is too large");
                }
                chunks.push(result.value);
            }
        } finally {
            reader.releaseLock();
        }
    }
    const value = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
        value.set(chunk, offset);
        offset += chunk.length;
    }
    if (!response.ok) {
        throw new Error(`Relay request failed (${response.status}): ${utf8Decode(value)}`);
    }
    return value;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid relay ${name}`);
    }
    return value as Record<string, unknown>;
}

function readChallenge(value: Uint8Array): Challenge {
    const input = object(JSON.parse(utf8Decode(value)) as unknown, "challenge");
    if (
        typeof input.id !== "string" ||
        typeof input.nonce !== "string" ||
        typeof input.expiresAt !== "number" ||
        !Number.isSafeInteger(input.expiresAt)
    ) {
        throw new Error("Invalid relay challenge");
    }
    return {
        id: input.id,
        nonce: decodeBase64Url(input.nonce),
        expiresAt: input.expiresAt,
    };
}

function proofBytes(
    challenge: Challenge,
    topic: RelayTopic,
    since: bigint,
    limit: number,
    waitMilliseconds: number,
): Uint8Array {
    return canonicalJsonBytes({
        challengeId: challenge.id,
        nonce: encodeBase64Url(challenge.nonce),
        topic: relayTopicToJson(topic),
        since: since.toString(),
        limit,
        waitMilliseconds,
    });
}

/** Browser-safe HTTP implementation of the single ordered relay transport. */
export class HttpRelayTransport implements RelayTransport {
    readonly #baseUrl: string;
    readonly #fetch: RelayFetch;

    constructor(baseUrl: string, relayFetch: RelayFetch = globalThis.fetch) {
        this.#baseUrl = baseUrl.replace(/\/+$/, "");
        this.#fetch = relayFetch;
    }

    /** Publish one signed durable event. */
    async publish(event: SignedRelayEvent, signal?: AbortSignal): Promise<PublishOutcome> {
        const response = await this.#fetch(`${this.#baseUrl}/v1/events`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: body(encodeSignedRelayEventWire(event)),
            ...(signal === undefined ? {} : { signal }),
        });
        const input = object(
            JSON.parse(utf8Decode(await responseBytes(response, 4096))) as unknown,
            "publish response",
        );
        if (typeof input.seq !== "string" || typeof input.duplicate !== "boolean") {
            throw new Error("Invalid relay publish response");
        }
        return { seq: BigInt(input.seq), duplicate: input.duplicate };
    }

    /** Read one retained event page, automatically proving protected reads. */
    async readEvents(
        access: TopicAccess,
        since: bigint,
        limit: number = 256,
        waitMilliseconds: number = 0,
        signal?: AbortSignal,
    ): Promise<EventPage> {
        let proof: { readonly challengeId: string; readonly signature: string } | undefined;
        if (access.topic.type !== "write") {
            if (access.readSecretKey === undefined || access.readSecretKey.length !== 32) {
                throw new Error("Protected topic read requires a 32-byte secret key");
            }
            if (!equalBytes(ed25519.getPublicKey(access.readSecretKey), access.topic.readKey)) {
                throw new Error("Read secret key does not match the topic capability");
            }
            const challengeResponse = await this.#fetch(`${this.#baseUrl}/v1/read-challenges`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ topic: relayTopicToJson(access.topic) }),
                ...(signal === undefined ? {} : { signal }),
            });
            const challenge = readChallenge(await responseBytes(challengeResponse, 4096));
            proof = {
                challengeId: challenge.id,
                signature: encodeBase64Url(
                    ed25519.sign(
                        proofBytes(challenge, access.topic, since, limit, waitMilliseconds),
                        access.readSecretKey,
                    ),
                ),
            };
        }
        const response = await this.#fetch(`${this.#baseUrl}/v1/events/read`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                topic: relayTopicToJson(access.topic),
                since: since.toString(),
                limit,
                waitMilliseconds,
                ...(proof === undefined ? {} : { proof }),
            }),
            ...(signal === undefined ? {} : { signal }),
        });
        return decodeEventPageWire(await responseBytes(response, 32 * 1024 * 1024));
    }
}
