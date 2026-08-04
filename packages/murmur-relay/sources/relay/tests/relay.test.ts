import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { afterEach, describe, expect, test } from "vitest";
import {
    readProofSigningBytes,
    relayEventSigningBytes,
    type ReadProof,
    type RelayTopic,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { SqliteRelayStore } from "../../storage/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { RelayService } from "../index.js";

const services: RelayService[] = [];
let now = 1_000_000;

function event(
    secretKey: Uint8Array,
    topic: RelayTopic,
    payload: string,
    options: { expiresAt?: number; collapseKey?: Uint8Array } = {},
): SignedRelayEvent {
    const unsigned: SignedRelayEvent = {
        version: 1,
        id: encodeBase64Url(randomBytes(32)),
        topic,
        author: { signingKey: ed25519.getPublicKey(secretKey) },
        createdAt: now,
        ...(options.expiresAt === undefined ? {} : { expiresAt: options.expiresAt }),
        ...(options.collapseKey === undefined ? {} : { collapseKey: options.collapseKey }),
        payload: new TextEncoder().encode(payload),
        signature: new Uint8Array(64),
    };
    return { ...unsigned, signature: ed25519.sign(relayEventSigningBytes(unsigned), secretKey) };
}

function service(): RelayService {
    const value = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
    services.push(value);
    return value;
}

function readProof(
    relay: RelayService,
    topic: Exclude<RelayTopic, { type: "write" }>,
    secretKey: Uint8Array,
    since: bigint = 0n,
    limit: number = 256,
    wait: number = 0,
): ReadProof {
    const challenge = relay.issueReadChallenge(topic);
    return {
        challengeId: challenge.id,
        signature: ed25519.sign(
            readProofSigningBytes(challenge, topic, since, limit, wait),
            secretKey,
        ),
    };
}

afterEach(async () => {
    await Promise.all(services.splice(0).map((item) => item.close()));
    now = 1_000_000;
});

describe("ordered relay", () => {
    test("enforces typed read/write capabilities and one-use read proofs", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const stranger = randomBytes(32);
        const topic = {
            type: "read-write" as const,
            name: "group",
            readKey: ed25519.getPublicKey(owner),
            writeKey: ed25519.getPublicKey(owner),
        };
        await expect(relay.publish(event(stranger, topic, "no"))).rejects.toMatchObject({
            status: 403,
        });
        await relay.publish(event(owner, topic, "yes"));
        await expect(relay.readEvents(topic, 0n)).rejects.toMatchObject({ status: 401 });
        const proof = readProof(relay, topic, owner);
        await expect(relay.readEvents(topic, 0n, 256, 0, proof)).resolves.toMatchObject({
            head: 1n,
        });
        await expect(relay.readEvents(topic, 0n, 256, 0, proof)).rejects.toMatchObject({
            status: 401,
        });

        const inbox = {
            type: "read" as const,
            name: "friends",
            readKey: ed25519.getPublicKey(owner),
        };
        await expect(relay.publish(event(stranger, inbox, "request"))).resolves.toMatchObject({
            seq: 1n,
        });
        await expect(
            relay.readEvents(inbox, 0n, 256, 0, readProof(relay, inbox, owner)),
        ).resolves.toMatchObject({ head: 1n });
    });

    test("keeps monotonic cursors across collapse and expiration holes", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "updates",
            writeKey: ed25519.getPublicKey(owner),
        };
        const collapseKey = new Uint8Array([7]);
        await relay.publish(event(owner, topic, "old", { collapseKey }));
        await relay.publish(event(owner, topic, "new", { collapseKey }));
        await relay.publish(event(owner, topic, "temporary", { expiresAt: now + 1 }));
        now += 2;
        const page = await relay.readEvents(topic, 0n);
        expect(page.head).toBe(3n);
        expect(page.events.map(({ seq }) => seq)).toEqual([2n]);
        expect(await relay.pruneExpired()).toBe(1);
        expect((await relay.readEvents(topic, 2n)).head).toBe(3n);
    });

    test("wakes a long poll after an authorized durable publish", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "live",
            writeKey: ed25519.getPublicKey(owner),
        };
        const waiting = relay.readEvents(topic, 0n, 256, 1_000);
        await relay.publish(event(owner, topic, "wake"));
        await expect(waiting).resolves.toMatchObject({ head: 1n });
    });
});
