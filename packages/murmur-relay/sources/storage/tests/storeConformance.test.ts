import { PGlite } from "@electric-sql/pglite";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { describe, expect, test } from "vitest";
import {
    relayEventSigningBytes,
    relayTopicId,
    type RelayTopic,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { PGliteDatabase, PostgresRelayStore, SqliteRelayStore, type RelayStore } from "../index.js";

const NOW = 5_000;

function signed(
    secretKey: Uint8Array,
    topic: RelayTopic,
    payload: number,
    collapseKey?: Uint8Array,
): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(randomBytes(32)),
        topic,
        author: { signingKey: ed25519.getPublicKey(secretKey) },
        createdAt: NOW,
        ...(collapseKey === undefined ? {} : { collapseKey }),
        payload: new Uint8Array([payload]),
        signature: new Uint8Array(64),
    };
    return { ...unsigned, signature: ed25519.sign(relayEventSigningBytes(unsigned), secretKey) };
}

async function stores(): Promise<readonly RelayStore[]> {
    return [
        new SqliteRelayStore(":memory:"),
        await PostgresRelayStore.create(new PGliteDatabase(new PGlite())),
    ];
}

describe("relay store conformance", () => {
    test("SQLite and PGlite preserve heads while collapse removes older rows", async () => {
        const secretKey = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "conformance",
            writeKey: ed25519.getPublicKey(secretKey),
        };
        for (const store of await stores()) {
            try {
                const topicId = relayTopicId(topic);
                const key = new Uint8Array([1, 2, 3]);
                expect(
                    (await store.publish(signed(secretKey, topic, 1, key), topicId, NOW)).seq,
                ).toBe(1n);
                expect(
                    (await store.publish(signed(secretKey, topic, 2, key), topicId, NOW)).seq,
                ).toBe(2n);
                const page = await store.readEvents(topicId, 0n, 100, NOW, {
                    maximumEncodedBytes: 1_000_000,
                });
                expect(page.head).toBe(2n);
                expect(page.events.map(({ seq }) => seq)).toEqual([2n]);
            } finally {
                await store.close();
            }
        }
    });
});
