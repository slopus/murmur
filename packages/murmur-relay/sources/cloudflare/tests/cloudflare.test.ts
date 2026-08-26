import { describe, expect, test } from "vitest";
import { signedDeliveryToJson } from "../../protocol/index.js";
import { identity, recipients, secret, signedDelivery } from "../../protocol/tests/helpers.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { MurmurFanoutDurableObject } from "../fanoutDurableObject.js";
import { MurmurInboxDurableObject } from "../inboxDurableObject.js";
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

const unusedNamespace: DurableObjectNamespaceLike = {
    idFromName: (name) => new NamedId(name),
    get: () => ({ fetch: async () => Response.json({ error: "unused" }, { status: 500 }) }),
};

describe("Cloudflare durable fanout", () => {
    test("rejects duplicate keys on internal Fetch JSON boundaries", async () => {
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: unusedNamespace,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
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
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
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

    test("purges exact owner-linked session deliveries and rejects replay", async () => {
        const now = Date.now();
        const ownerSecret = secret(11);
        const owner = identity(ownerSecret);
        const otherOwnerSecret = secret(12);
        const otherOwner = identity(otherOwnerSecret);
        const bob = identity(secret(13));
        const carol = identity(secret(14));
        const sessionId = new Uint8Array(32).fill(21);
        const otherSessionId = new Uint8Array(32).fill(22);
        const inboxes = new InboxNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        const linked = signedDelivery(ownerSecret, recipients(bob, carol), {
            id: 31,
            now,
            expiresAt: now + 60_000,
            ownerAccount: owner,
            sessionId,
        });
        const otherSession = signedDelivery(ownerSecret, recipients(bob), {
            id: 32,
            now,
            expiresAt: now + 60_000,
            ownerAccount: owner,
            sessionId: otherSessionId,
        });
        const otherOwnerDelivery = signedDelivery(otherOwnerSecret, recipients(carol), {
            id: 33,
            now,
            expiresAt: now + 60_000,
            ownerAccount: otherOwner,
            sessionId,
        });
        for (const delivery of [linked, otherSession, otherOwnerDelivery]) {
            const response = await fanout.fetch(
                new Request("https://murmur.internal/v2/publish", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({
                        delivery: signedDeliveryToJson(delivery),
                        admissionPrincipal: "account-1",
                    }),
                }),
            );
            expect(response.status).toBe(200);
        }
        await fanout.alarm();
        const bobStorage = inboxes.states.get(encodeBase64Url(bob))!.storage;
        const carolStorage = inboxes.states.get(encodeBase64Url(carol))!.storage;
        expect((await bobStorage.list({ prefix: "inbox:event:" })).size).toBe(2);
        expect((await carolStorage.list({ prefix: "inbox:event:" })).size).toBe(2);
        const bobGeneration = (
            (await bobStorage.get("inbox:meta")) as { readonly generation: string }
        ).generation;
        const carolGeneration = (
            (await carolStorage.get("inbox:meta")) as { readonly generation: string }
        ).generation;

        const deletion = signedDelivery(ownerSecret, [], {
            id: 34,
            now,
            expiresAt: now + 60_000,
            ciphertext: new TextEncoder().encode(
                JSON.stringify({
                    version: 1,
                    type: "delete_session",
                    sessionId: encodeBase64Url(sessionId),
                }),
            ),
        });
        const deleteRequest = (requestDelivery = deletion): Promise<Response> =>
            fanout.fetch(
                new Request("https://murmur.internal/v2/delete", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify({ delivery: signedDeliveryToJson(requestDelivery) }),
                }),
            );
        const deleted = await deleteRequest();
        expect(deleted.status).toBe(200);
        expect(await deleted.json()).toEqual({ removed: 2 });
        expect((await bobStorage.list({ prefix: "inbox:event:" })).size).toBe(1);
        expect((await carolStorage.list({ prefix: "inbox:event:" })).size).toBe(1);
        expect(
            ((await bobStorage.get("inbox:meta")) as { readonly generation: string }).generation,
        ).not.toBe(bobGeneration);
        expect(
            ((await carolStorage.get("inbox:meta")) as { readonly generation: string }).generation,
        ).not.toBe(carolGeneration);

        const replay = await deleteRequest(
            signedDelivery(ownerSecret, [], {
                id: 34,
                now: now + 1,
                expiresAt: now + 60_001,
                ciphertext: deletion.ciphertext,
            }),
        );
        expect(replay.status).toBe(409);
        expect(await replay.json()).toEqual({ error: "replay" });
        const republish = await fanout.fetch(
            new Request("https://murmur.internal/v2/publish", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({
                    delivery: signedDeliveryToJson(
                        signedDelivery(ownerSecret, recipients(bob), {
                            id: 35,
                            now,
                            expiresAt: now + 60_000,
                            ownerAccount: owner,
                            sessionId,
                        }),
                    ),
                    admissionPrincipal: "account-1",
                }),
            }),
        );
        expect(republish.status).toBe(409);
        expect(await republish.json()).toEqual({ error: "session_deleted" });
    });

    test("absorbs a pre-deletion fanout manifest that reaches its inbox late", async () => {
        const now = Date.now();
        const ownerSecret = secret(41);
        const owner = identity(ownerSecret);
        const recipient = identity(secret(42));
        const sessionId = new Uint8Array(32).fill(43);
        const inboxes = new InboxNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanoutState = new MemoryState();
        const fanout = new MurmurFanoutDurableObject(fanoutState, environment);
        const pending = signedDelivery(ownerSecret, recipients(recipient), {
            id: 44,
            now,
            expiresAt: now + 60_000,
            ownerAccount: owner,
            sessionId,
        });
        expect(
            (
                await fanout.fetch(
                    new Request("https://murmur.internal/v2/publish", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({
                            delivery: signedDeliveryToJson(pending),
                            admissionPrincipal: "account-1",
                        }),
                    }),
                )
            ).status,
        ).toBe(200);

        const deletion = signedDelivery(ownerSecret, [], {
            id: 45,
            now,
            expiresAt: now + 60_000,
            ciphertext: new TextEncoder().encode(
                JSON.stringify({
                    version: 1,
                    type: "delete_session",
                    sessionId: encodeBase64Url(sessionId),
                }),
            ),
        });
        const deleted = await fanout.fetch(
            new Request("https://murmur.internal/v2/delete", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ delivery: signedDeliveryToJson(deletion) }),
            }),
        );
        expect(deleted.status).toBe(200);
        expect(await deleted.json()).toEqual({ removed: 0 });

        await fanout.alarm();
        const inbox = inboxes.states.get(encodeBase64Url(recipient))!.storage;
        expect((await inbox.list({ prefix: "inbox:event:" })).size).toBe(0);
        expect((await fanoutState.storage.list({ prefix: "fanout:pending:" })).size).toBe(0);
    });
});
