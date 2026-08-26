import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, test } from "vitest";
import { signedDeliveryToJson } from "../../protocol/index.js";
import type {
    PrivateGroupPresentationChallenge,
    PrivateGroupStateLimits,
    PrivateGroupStateRecord,
} from "../../privateGroupState/types.js";
import { identity, recipients, secret, signedDelivery } from "../../protocol/tests/helpers.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { MurmurFanoutDurableObject } from "../fanoutDurableObject.js";
import { MurmurInboxDurableObject } from "../inboxDurableObject.js";
import {
    CloudflarePrivateGroupStateStore,
    MurmurPrivateGroupDurableObject,
    handleCloudflarePrivateGroupRequest,
} from "../privateGroupDurableObject.js";
import type {
    CloudflareServerWebSocket,
    DurableObjectIdLike,
    DurableObjectListOptions,
    DurableObjectNamespaceLike,
    DurableObjectStateLike,
    DurableObjectStorageLike,
    DurableObjectStubLike,
    DurableObjectTransactionLike,
    MurmurCloudflareEnvironment,
} from "../types.js";

class MemoryStorage implements DurableObjectStorageLike {
    readonly values = new Map<string, unknown>();
    alarm: number | null = null;

    async get<T>(key: string): Promise<T | undefined> {
        return this.values.get(key) as T | undefined;
    }

    async put<T>(key: string, value: T): Promise<void> {
        this.values.set(key, structuredClone(value));
    }

    async delete(key: string | readonly string[]): Promise<boolean | number> {
        if (typeof key === "string") return this.values.delete(key);
        let removed = 0;
        for (const item of key) if (this.values.delete(item)) removed += 1;
        return removed;
    }

    async list<T>(options: DurableObjectListOptions = {}): Promise<Map<string, T>> {
        const result = new Map<string, T>();
        const keys = [...this.values.keys()].sort();
        for (const key of keys) {
            if (options.prefix !== undefined && !key.startsWith(options.prefix)) continue;
            if (options.startAfter !== undefined && key <= options.startAfter) continue;
            if (options.end !== undefined && key >= options.end) continue;
            result.set(key, structuredClone(this.values.get(key)) as T);
            if (options.limit !== undefined && result.size >= options.limit) break;
        }
        return result;
    }

    async transaction<T>(
        closure: (transaction: DurableObjectTransactionLike) => Promise<T>,
    ): Promise<T> {
        return closure(this);
    }

    async getAlarm(): Promise<number | null> {
        return this.alarm;
    }

    async setAlarm(scheduledTime: number): Promise<void> {
        this.alarm = scheduledTime;
    }
}

class MemoryState implements DurableObjectStateLike {
    readonly storage = new MemoryStorage();
    readonly sockets: CloudflareServerWebSocket[] = [];

    acceptWebSocket(socket: CloudflareServerWebSocket): void {
        this.sockets.push(socket);
    }

    getWebSockets(): readonly CloudflareServerWebSocket[] {
        return this.sockets;
    }

    waitUntil(_promise: Promise<unknown>): void {}
}

class NamedId implements DurableObjectIdLike {
    constructor(readonly name: string) {}

    toString(): string {
        return this.name;
    }
}

class InboxNamespace implements DurableObjectNamespaceLike {
    readonly states = new Map<string, MemoryState>();
    readonly objects = new Map<string, MurmurInboxDurableObject>();
    failNameOnce: string | undefined;
    #environment: MurmurCloudflareEnvironment | undefined;

    setEnvironment(environment: MurmurCloudflareEnvironment): void {
        this.#environment = environment;
    }

    idFromName(name: string): DurableObjectIdLike {
        return new NamedId(name);
    }

    get(id: DurableObjectIdLike): DurableObjectStubLike {
        const name = id.toString();
        return {
            fetch: async (request) => {
                if (this.failNameOnce === name) {
                    this.failNameOnce = undefined;
                    return Response.json({ error: "overloaded" }, { status: 503 });
                }
                let object = this.objects.get(name);
                if (object === undefined) {
                    const state = new MemoryState();
                    this.states.set(name, state);
                    object = new MurmurInboxDurableObject(state, this.#environment!);
                    this.objects.set(name, object);
                }
                return object.fetch(request);
            },
        };
    }
}

class PrivateGroupNamespace implements DurableObjectNamespaceLike {
    readonly states = new Map<string, MemoryState>();
    readonly objects = new Map<string, MurmurPrivateGroupDurableObject>();
    readonly requestedNames: string[] = [];
    #environment: MurmurCloudflareEnvironment | undefined;

    setEnvironment(environment: MurmurCloudflareEnvironment): void {
        this.#environment = environment;
    }

    idFromName(name: string): DurableObjectIdLike {
        this.requestedNames.push(name);
        return new NamedId(name);
    }

    get(id: DurableObjectIdLike): DurableObjectStubLike {
        const name = id.toString();
        return {
            fetch: async (request) => {
                let object = this.objects.get(name);
                if (object === undefined) {
                    const state = new MemoryState();
                    this.states.set(name, state);
                    object = new MurmurPrivateGroupDurableObject(state, this.#environment!);
                    this.objects.set(name, object);
                }
                return object.fetch(request);
            },
        };
    }
}

const unusedNamespace: DurableObjectNamespaceLike = {
    idFromName: (name) => new NamedId(name),
    get: () => ({ fetch: async () => Response.json({ error: "unused" }, { status: 500 }) }),
};

describe("Cloudflare durable fanout", () => {
    test("rejects duplicate keys on internal Fetch JSON boundaries", async () => {
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: unusedNamespace,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_PRIVATE_GROUPS: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_PRIVATE_GROUP_SECRET: encodeBase64Url(new Uint8Array(32).fill(19)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        const boundaries = [
            new MurmurFanoutDurableObject(new MemoryState(), environment),
            new MurmurInboxDurableObject(new MemoryState(), environment),
        ];
        const paths = ["/v2/publish", "/v2/insert"];
        for (let index = 0; index < boundaries.length; index += 1) {
            const response = await boundaries[index]!.fetch(
                new Request(`https://murmur.internal${paths[index]!}`, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: '{"value":1,"\\u0076alue":2}',
                }),
            );
            expect(response.status).toBe(400);
            expect(await response.json()).toEqual({ error: "duplicate_json_key" });
        }
    });

    test("retries a partial manifest before inserting a later event", async () => {
        const now = Date.now();
        const alice = secret(1);
        const bob = identity(secret(2));
        const carol = identity(secret(3));
        const inboxes = new InboxNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_PRIVATE_GROUPS: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_PRIVATE_GROUP_SECRET: encodeBase64Url(new Uint8Array(32).fill(19)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanoutState = new MemoryState();
        const fanout = new MurmurFanoutDurableObject(fanoutState, environment);
        const first = signedDelivery(alice, recipients(bob, carol), {
            id: 1,
            now,
            expiresAt: now + 60_000,
        });
        const second = signedDelivery(alice, recipients(bob), {
            id: 2,
            now,
            expiresAt: now + 60_000,
        });
        const publish = (delivery: typeof first): Promise<Response> =>
            fanout.fetch(
                new Request("https://murmur.internal/v2/publish", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({
                        delivery: signedDeliveryToJson(delivery),
                        admissionPrincipal: "account-1",
                    }),
                }),
            );
        const firstOutcome = (await (await publish(first)).json()) as {
            readonly eventId: string;
        };
        const secondOutcome = (await (await publish(second)).json()) as {
            readonly eventId: string;
        };
        const bobName = encodeBase64Url(bob);
        const carolName = encodeBase64Url(carol);
        inboxes.failNameOnce = bobName;

        await fanout.alarm();
        expect(
            await inboxes.states.get(carolName)?.storage.get(`inbox:event:${firstOutcome.eventId}`),
        ).toBeDefined();
        expect(inboxes.states.get(bobName)).toBeUndefined();
        expect(
            await inboxes.states
                .get(carolName)
                ?.storage.get(`inbox:event:${secondOutcome.eventId}`),
        ).toBeUndefined();

        await fanout.alarm();
        const bobStorage = inboxes.states.get(bobName)?.storage;
        expect(await bobStorage?.get(`inbox:event:${firstOutcome.eventId}`)).toBeDefined();
        expect(await bobStorage?.get(`inbox:event:${secondOutcome.eventId}`)).toBeDefined();
        expect(firstOutcome.eventId < secondOutcome.eventId).toBe(true);
        expect((await fanoutState.storage.list({ prefix: "fanout:pending:" })).size).toBe(0);
    });
});

const privateGroupLimits: PrivateGroupStateLimits = {
    maximumGroups: 10,
    maximumRecordBytes: 1_000_000,
    maximumSealedStateBytes: 500_000,
    maximumMembersPerGroup: 10,
    maximumPendingChallenges: 1,
};

function privateBytes(seed: number, length = 32): Uint8Array {
    return Uint8Array.from({ length }, (_, index) => (seed + index * 17) & 0xff);
}

function privateRecord(
    opaqueGroupId: Uint8Array,
    revision: number,
    previousRevisionHash: Uint8Array | null,
    members = [
        { entry: privateBytes(31, 48), role: "owner" as const },
        { entry: privateBytes(41, 48), role: "member" as const },
    ],
): PrivateGroupStateRecord {
    return {
        version: 1,
        opaqueGroupId,
        publicParameters: privateBytes(21, 96),
        revision,
        previousRevisionHash,
        members,
        sealedState: privateBytes(51, 128),
        revisionAuthenticator: privateBytes(61),
    };
}

function privateChallenge(
    opaqueGroupId: Uint8Array,
    replayNonce: Uint8Array,
    expiresAt: number,
): PrivateGroupPresentationChallenge {
    return {
        opaqueGroupId,
        entry: privateBytes(31, 48),
        role: "owner",
        operation: "create",
        replayNonce,
        context: privateBytes(71, 64),
        expiresAt,
    };
}

describe("Cloudflare private-group state", () => {
    test("pins one clean object per opaque group and persists canonical state", async () => {
        const now = 1_800_000_000_000;
        const groupId = privateBytes(11);
        const state = new MemoryState();
        const store = new CloudflarePrivateGroupStateStore(state, groupId);
        await store.pin();

        const firstRecord = privateRecord(groupId, 1, null);
        const firstRaw = privateBytes(81, 256);
        const firstHash = sha256(firstRaw);
        const created = await store.create(
            firstRecord,
            firstHash,
            firstRaw,
            privateGroupLimits,
            now,
        );
        const duplicate = await store.create(
            firstRecord,
            firstHash,
            firstRaw,
            privateGroupLimits,
            now,
        );
        expect(duplicate.canonicalVersion).toBe(created.canonicalVersion);
        expect(await store.hasMember(groupId, firstRecord.members[1]!.entry, "member")).toBe(true);

        const secondRecord = privateRecord(groupId, 2, firstHash, [
            { entry: firstRecord.members[0]!.entry, role: "owner" },
        ]);
        const secondRaw = privateBytes(91, 256);
        const secondHash = sha256(secondRaw);
        const replaced = await store.replace(
            created.canonicalVersion,
            firstHash,
            secondRecord,
            secondHash,
            secondRaw,
            privateGroupLimits,
            now,
        );
        expect(replaced.canonicalVersion > created.canonicalVersion).toBe(true);
        expect(replaced.replacesVersion).toBe(created.canonicalVersion);
        const replacementRetry = await store.replace(
            created.canonicalVersion,
            firstHash,
            secondRecord,
            secondHash,
            secondRaw,
            privateGroupLimits,
            now,
        );
        expect(replacementRetry.canonicalVersion).toBe(replaced.canonicalVersion);
        expect(await store.hasMember(groupId, firstRecord.members[1]!.entry, "member")).toBe(false);
        expect((await store.read(groupId))?.record.revision).toBe(2);

        const other = new CloudflarePrivateGroupStateStore(state, privateBytes(12));
        await expect(other.pin()).rejects.toThrow("pinned to another group");
    });

    test("bounds, expires, and consumes one-use presentation challenges", async () => {
        const now = 1_800_000_000_000;
        const groupId = privateBytes(11);
        const store = new CloudflarePrivateGroupStateStore(new MemoryState(), groupId);
        await store.pin();
        const first = privateChallenge(groupId, privateBytes(101), now + 10);
        const second = privateChallenge(groupId, privateBytes(102), now + 20);
        await store.storeChallenge(first, 1, now);
        await expect(store.storeChallenge(second, 1, now)).rejects.toThrow("quota");
        await store.storeChallenge(second, 1, now + 10);
        expect(await store.consumeChallenge(first.replayNonce, now + 10)).toBeUndefined();
        expect(await store.consumeChallenge(second.replayNonce, now + 10)).toEqual(second);
        expect(await store.consumeChallenge(second.replayNonce, now + 10)).toBeUndefined();
    });

    test("keeps credential issuance stateless and routes group operations by canonical header", async () => {
        const groups = new PrivateGroupNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: unusedNamespace,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_PRIVATE_GROUPS: groups,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(privateBytes(201)),
            MURMUR_PRIVATE_GROUP_SECRET: encodeBase64Url(privateBytes(211)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        groups.setEnvironment(environment);
        const config = await handleCloudflarePrivateGroupRequest(
            new Request("https://relay.test/v1/private-groups/config"),
            environment,
        );
        expect(config?.status).toBe(200);
        expect(groups.requestedNames).toEqual([]);
        const credentialChallenge = await handleCloudflarePrivateGroupRequest(
            new Request("https://relay.test/v1/private-groups/credentials/challenge", {
                method: "POST",
                body: JSON.stringify({ accountIdentifier: encodeBase64Url(privateBytes(1)) }),
            }),
            environment,
        );
        expect(credentialChallenge?.status).toBe(200);
        expect(groups.requestedNames).toEqual([]);
        const reusedSecret = await handleCloudflarePrivateGroupRequest(
            new Request("https://relay.test/v1/private-groups/config"),
            {
                ...environment,
                MURMUR_PRIVATE_GROUP_SECRET: environment.MURMUR_RELAY_TOKEN_SECRET,
            },
        );
        expect(reusedSecret?.status).toBe(500);

        const groupId = privateBytes(11);
        const encodedGroupId = encodeBase64Url(groupId);
        const body = JSON.stringify({
            opaqueGroupId: encodedGroupId,
            entry: encodeBase64Url(privateBytes(31, 48)),
            role: "owner",
            operation: "create",
        });
        const missingHeader = await handleCloudflarePrivateGroupRequest(
            new Request("https://relay.test/v1/private-groups/challenges", {
                method: "POST",
                body,
            }),
            environment,
        );
        expect(missingHeader?.status).toBe(400);

        const mismatchedBody = await handleCloudflarePrivateGroupRequest(
            new Request("https://relay.test/v1/private-groups/challenges", {
                method: "POST",
                headers: { "x-murmur-private-group": encodedGroupId },
                body: JSON.stringify({
                    opaqueGroupId: encodeBase64Url(privateBytes(12)),
                    entry: encodeBase64Url(privateBytes(31, 48)),
                    role: "owner",
                    operation: "create",
                }),
            }),
            environment,
        );
        expect(mismatchedBody?.status).toBe(400);

        const challenge = await handleCloudflarePrivateGroupRequest(
            new Request("https://relay.test/v1/private-groups/challenges", {
                method: "POST",
                headers: { "x-murmur-private-group": encodedGroupId },
                body,
            }),
            environment,
        );
        expect(challenge?.status).toBe(200);
        expect(groups.requestedNames).toEqual([encodedGroupId, encodedGroupId]);
        expect(await groups.states.get(encodedGroupId)?.storage.get("private-group:id")).toBe(
            encodedGroupId,
        );
    });
});
