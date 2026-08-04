import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import { afterEach, describe, expect, test } from "vitest";
import {
    readProofSigningBytes,
    relayEventFingerprint,
    relayEventSigningBytes,
    type ReadProof,
    type RelayTopic,
    type SignedRelayEvent,
} from "../../protocol/index.js";
import { SqliteRelayStore, type EventPage, type PageReadConstraints } from "../../storage/index.js";
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

async function readProof(
    relay: RelayService,
    topic: Exclude<RelayTopic, { type: "write" }>,
    secretKey: Uint8Array,
    since: bigint = 0n,
    limit: number = 256,
    wait: number = 0,
): Promise<ReadProof> {
    const challenge = await relay.issueReadChallenge(topic);
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
    test("fingerprints the complete signed event including its signature", () => {
        const owner = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "fingerprint",
            writeKey: ed25519.getPublicKey(owner),
        };
        const original = event(owner, topic, "body");
        const signature = original.signature.slice();
        signature[0] = signature[0]! ^ 1;
        const changedSignature = {
            ...original,
            signature,
        };
        expect(relayEventFingerprint(changedSignature)).not.toEqual(
            relayEventFingerprint(original),
        );
    });

    test("rejects malformed direct-service descriptors before hashing or storage", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "strict",
            writeKey: ed25519.getPublicKey(owner),
        };
        const valid = event(owner, topic, "body");
        await expect(
            relay.publish({
                ...valid,
                topic: { ...topic, extra: true } as unknown as RelayTopic,
            }),
        ).rejects.toMatchObject({ status: 400 });
        await expect(
            relay.issueReadChallenge({
                type: "read",
                name: "é",
                readKey: topic.writeKey,
            }),
        ).rejects.toMatchObject({ status: 400 });
    });

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
        const proof = await readProof(relay, topic, owner);
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
            relay.readEvents(inbox, 0n, 256, 0, await readProof(relay, inbox, owner)),
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

    test("keeps exact retries idempotent after timestamp and event expiration", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "retry",
            writeKey: ed25519.getPublicKey(owner),
        };
        const original = event(owner, topic, "original", { expiresAt: now + 1 });
        await expect(relay.publish(original)).resolves.toEqual({ seq: 1n, duplicate: false });
        now += 10 * 60 * 1_000;
        expect(await relay.pruneExpired()).toBe(1);
        await expect(relay.publish(original)).resolves.toEqual({ seq: 1n, duplicate: true });

        const changedUnsigned: SignedRelayEvent = {
            ...original,
            payload: new TextEncoder().encode("changed"),
            signature: new Uint8Array(64),
        };
        const changed = {
            ...changedUnsigned,
            signature: ed25519.sign(relayEventSigningBytes(changedUnsigned), owner),
        };
        await expect(relay.publish(changed)).rejects.toMatchObject({
            status: 409,
            body: { error: "id_collision" },
        });
    });

    test("returns head-only progress without parking a long poll", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const topic = {
            type: "write" as const,
            name: "head-only",
            writeKey: ed25519.getPublicKey(owner),
        };
        await relay.publish(event(owner, topic, "gone", { expiresAt: now + 1 }));
        now += 2;
        await expect(relay.readEvents(topic, 0n, 256, 1_000)).resolves.toMatchObject({
            events: [],
            head: 1n,
            exhausted: true,
        });
    });

    test("register recheck wakes when only the topic head raced forward", async () => {
        class RacingHeadStore extends SqliteRelayStore {
            #reads = 0;

            override async readEvents(
                _topicId: string,
                _since: bigint,
                _limit: number,
                _observedAt: number,
                _constraints: PageReadConstraints,
            ): Promise<EventPage> {
                this.#reads += 1;
                return {
                    events: [],
                    head: this.#reads === 1 ? 0n : 1n,
                    exhausted: true,
                };
            }
        }
        const relay = new RelayService(new RacingHeadStore(":memory:"));
        services.push(relay);
        const topic = {
            type: "write" as const,
            name: "racing-head",
            writeKey: ed25519.getPublicKey(randomBytes(32)),
        };
        await expect(relay.readEvents(topic, 0n, 256, 1_000)).resolves.toMatchObject({
            events: [],
            head: 1n,
        });
    });

    test("bounds outstanding challenges and admits after indexed expiration cleanup", async () => {
        const relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                maximumOutstandingReadChallenges: 1,
                readChallengeLifetimeMilliseconds: 1,
            },
            undefined,
            () => now,
        );
        services.push(relay);
        const topic = {
            type: "read" as const,
            name: "bounded-challenges",
            readKey: ed25519.getPublicKey(randomBytes(32)),
        };
        await relay.issueReadChallenge(topic);
        await expect(relay.issueReadChallenge(topic)).rejects.toMatchObject({ status: 503 });
        now += 2;
        await expect(relay.issueReadChallenge(topic)).resolves.toBeDefined();
    });

    test("runtime-validates direct read cursors, topics, and proof shapes", async () => {
        const relay = service();
        const owner = randomBytes(32);
        const publicTopic = {
            type: "write" as const,
            name: "direct-runtime",
            writeKey: ed25519.getPublicKey(owner),
        };
        await expect(relay.readEvents(publicTopic, 0.5 as unknown as bigint)).rejects.toMatchObject(
            { status: 400, body: { error: "malformed" } },
        );
        await expect(
            relay.readEvents({ ...publicTopic, extra: true } as unknown as RelayTopic, 0n),
        ).rejects.toMatchObject({ status: 400 });

        const protectedTopic = {
            type: "read" as const,
            name: "protected-runtime",
            readKey: ed25519.getPublicKey(owner),
        };
        await expect(
            relay.readEvents(protectedTopic, 0n, 256, 0, {} as ReadProof),
        ).rejects.toMatchObject({ status: 400, body: { error: "malformed" } });
        await expect(
            relay.readEvents(protectedTopic, 0n, 256, 0, {
                challengeId: "missing",
                signature: new Uint8Array(64),
            }),
        ).rejects.toMatchObject({ status: 401, body: { error: "unauthorized" } });
    });
});
