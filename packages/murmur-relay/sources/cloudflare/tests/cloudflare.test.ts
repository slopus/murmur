import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { describe, expect, test } from "vitest";
import { LocalDirectoryTicketIssuer } from "../../directory/index.js";
import { signedDeliveryToJson, type SignedDelivery } from "../../protocol/index.js";
import { identity, recipients, secret, signedDelivery } from "../../protocol/tests/helpers.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { MurmurFanoutDurableObject } from "../fanoutDurableObject.js";
import { MurmurInboxDurableObject } from "../inboxDurableObject.js";
import { deriveCloudflareDirectoryTicketSecret } from "../impl/cloudflareCodec.js";
import type {
    CloudflareServerWebSocket,
    DurableObjectIdLike,
    DurableObjectListOptions,
    DurableObjectNamespaceLike,
    DurableObjectStateLike,
    DurableObjectStorageLike,
    DurableObjectStubLike,
    DurableObjectSqlCursorLike,
    DurableObjectSqlLike,
    DurableObjectSqlValue,
    DurableObjectTransactionLike,
    MurmurCloudflareEnvironment,
} from "../types.js";

class CapturingSocket implements CloudflareServerWebSocket {
    readonly messages: string[] = [];
    attachment: ReturnType<CloudflareServerWebSocket["deserializeAttachment"]> = {
        device: encodeBase64Url(identity(secret(120))),
        admissionPrincipal: "account-120",
        expiresAt: Date.now() + 60_000,
    };

    send(message: string): void {
        this.messages.push(message);
    }

    close(): void {}

    serializeAttachment(value: NonNullable<typeof this.attachment>): void {
        this.attachment = value;
    }

    deserializeAttachment(): typeof this.attachment {
        return this.attachment;
    }
}

class MemoryStorage implements DurableObjectStorageLike {
    readonly values = new Map<string, unknown>();
    readonly #database = new DatabaseSync(":memory:");
    readonly sql: DurableObjectSqlLike = {
        exec: <Row extends Record<string, unknown>>(
            query: string,
            ...bindings: readonly DurableObjectSqlValue[]
        ): DurableObjectSqlCursorLike<Row> => {
            const normalized = query.trimStart().toUpperCase();
            let rows: Row[] = [];
            if (bindings.length === 0 && !normalized.startsWith("SELECT")) {
                this.#database.exec(query);
            } else {
                const statement = this.#database.prepare(query);
                const values = bindings.map((binding) =>
                    binding instanceof ArrayBuffer ? new Uint8Array(binding) : binding,
                ) as readonly SQLInputValue[];
                if (normalized.startsWith("SELECT")) {
                    rows = statement.all(...values) as Row[];
                } else {
                    statement.run(...values);
                }
            }
            return {
                toArray: () => rows,
                one: () => {
                    if (rows.length !== 1) throw new Error("Expected exactly one SQL row");
                    return rows[0]!;
                },
            };
        },
    };
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

    transactionSync<T>(closure: () => T): T {
        this.#database.exec("BEGIN IMMEDIATE");
        try {
            const result = closure();
            this.#database.exec("COMMIT");
            return result;
        } catch (error: unknown) {
            this.#database.exec("ROLLBACK");
            throw error;
        }
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

class FanoutNamespace implements DurableObjectNamespaceLike {
    object: MurmurFanoutDurableObject | undefined;

    idFromName(name: string): DurableObjectIdLike {
        return new NamedId(name);
    }

    get(): DurableObjectStubLike {
        return {
            fetch: (request) => this.object!.fetch(request),
        };
    }
}

function bytes(value: unknown): Uint8Array {
    return new TextEncoder().encode(JSON.stringify(value));
}

function internalRequest(path: string, body: unknown): Request {
    return new Request(`https://murmur.internal${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
    });
}

async function registerDevice(
    fanout: MurmurFanoutDurableObject,
    accountSecret: Uint8Array,
    deviceKey: Uint8Array,
    now: number,
    id: number,
): Promise<Response> {
    const delivery = signedDelivery(accountSecret, recipients(deviceKey), {
        id,
        now,
        expiresAt: now + 60_000,
        ciphertext: bytes({
            version: 1,
            type: "register",
            deviceKey: encodeBase64Url(deviceKey),
            resetGeneration: 0,
            keyPackage: encodeBase64Url(new Uint8Array([id, 1, 2])),
        }),
    });
    return fanout.fetch(
        internalRequest("/v2/roster/mutate", {
            delivery: signedDeliveryToJson(delivery),
            admissionPrincipal: `account-${id}`,
        }),
    );
}

async function publish(
    fanout: MurmurFanoutDurableObject,
    delivery: SignedDelivery,
    admissionPrincipal: string = "test-principal",
): Promise<Response> {
    return fanout.fetch(
        internalRequest("/v2/publish", {
            delivery: signedDeliveryToJson(delivery),
            admissionPrincipal,
        }),
    );
}

describe("Cloudflare durable fanout", () => {
    test("durably limits directory-ticket issuance per authenticated principal", async () => {
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: unusedNamespace,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        for (let index = 0; index < 8; index += 1) {
            const response = await fanout.fetch(
                internalRequest("/v2/directory-ticket/authorize", {
                    admissionPrincipal: "workos-user-1",
                }),
            );
            expect(response.status).toBe(200);
        }

        const throttled = await fanout.fetch(
            internalRequest("/v2/directory-ticket/authorize", {
                admissionPrincipal: "workos-user-1",
            }),
        );
        const otherPrincipal = await fanout.fetch(
            internalRequest("/v2/directory-ticket/authorize", {
                admissionPrincipal: "workos-user-2",
            }),
        );

        expect(throttled.status).toBe(429);
        await expect(throttled.json()).resolves.toMatchObject({
            error: "rate_limited",
        });
        expect(otherPrincipal.status).toBe(200);
    });

    test("routes terminal account deletion through the authenticated inbox", async () => {
        const now = Date.now();
        const accountSecret = secret(120);
        const fanoutNamespace = new FanoutNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: unusedNamespace,
            MURMUR_FANOUT: fanoutNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        fanoutNamespace.object = new MurmurFanoutDurableObject(new MemoryState(), environment);
        const inbox = new MurmurInboxDurableObject(new MemoryState(), environment);
        const socket = new CapturingSocket();
        const deletion = signedDelivery(accountSecret, [], {
            id: 120,
            now,
            expiresAt: now + 60_000,
            ciphertext: bytes({ version: 1, type: "delete_account" }),
        });
        await inbox.webSocketMessage(
            socket,
            JSON.stringify({
                version: 1,
                id: "AAAAAAAAAAAAAAAAAAAAAAAA",
                operation: "delete_account",
                body: signedDeliveryToJson(deletion),
            }),
        );
        expect(JSON.parse(socket.messages[0]!) as unknown).toMatchObject({
            status: 200,
            body: { deleted: true },
        });
    });

    test("derives a session-addressed fanout across current member inboxes", async () => {
        const now = Date.now();
        const ownerSecret = secret(121);
        const owner = identity(ownerSecret);
        const ownerDeviceSecret = secret(122);
        const ownerDevice = identity(ownerDeviceSecret);
        const memberSecret = secret(123);
        const member = identity(memberSecret);
        const memberDevice = identity(secret(124));
        const inboxes = new InboxNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        expect((await registerDevice(fanout, ownerSecret, ownerDevice, now, 121)).status).toBe(200);
        expect((await registerDevice(fanout, memberSecret, memberDevice, now, 123)).status).toBe(
            200,
        );
        const sessionId = new Uint8Array(32).fill(125);
        const delivery = signedDelivery(ownerDeviceSecret, [], {
            id: 125,
            now,
            expiresAt: now + 60_000,
            senderAccount: owner,
            ownerAccount: owner,
            sessionId,
            sessionControl: {
                version: 1,
                type: "create",
                epoch: 0n,
                members: recipients(owner, member),
                roles: {
                    owner,
                    admins: [],
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                    sendPolicy: "everyone",
                },
                coveredDevices: recipients(ownerDevice, memberDevice),
            },
        });
        expect((await publish(fanout, delivery)).status).toBe(200);
        await fanout.alarm();
        for (const device of [ownerDevice, memberDevice]) {
            const storage = inboxes.states.get(encodeBase64Url(device))!.storage;
            const queued = await storage.list({ prefix: "inbox:event:" });
            expect(
                [...queued.values()].some(
                    (value) =>
                        (value as { readonly delivery: { readonly sessionControl: unknown } })
                            .delivery.sessionControl !== null,
                ),
            ).toBe(true);
        }
    });

    test("enforces membership summaries, member identity, and send policy", async () => {
        const now = Date.now();
        const accountSecrets = [secret(130), secret(131), secret(132)];
        const accounts = accountSecrets.map(identity);
        const deviceSecrets = [secret(133), secret(134), secret(135)];
        const devices = deviceSecrets.map(identity);
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: unusedNamespace,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        for (let index = 0; index < accounts.length; index += 1) {
            expect(
                (
                    await registerDevice(
                        fanout,
                        accountSecrets[index]!,
                        devices[index]!,
                        now,
                        130 + index,
                    )
                ).status,
            ).toBe(200);
        }
        const sessionId = new Uint8Array(32).fill(136);
        const roles = {
            owner: accounts[0]!,
            admins: [] as readonly Uint8Array[],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
            sendPolicy: "admins" as const,
        };
        expect(
            (
                await publish(
                    fanout,
                    signedDelivery(deviceSecrets[0]!, [], {
                        id: 136,
                        now,
                        expiresAt: now + 60_000,
                        senderAccount: accounts[0]!,
                        ownerAccount: accounts[0]!,
                        sessionId,
                        sessionControl: {
                            version: 1,
                            type: "create",
                            epoch: 0n,
                            members: recipients(accounts[0]!, accounts[1]!),
                            roles,
                            coveredDevices: recipients(devices[0]!, devices[1]!),
                        },
                    }),
                )
            ).status,
        ).toBe(200);

        const memberSend = await publish(
            fanout,
            signedDelivery(deviceSecrets[1]!, [], {
                id: 137,
                now,
                expiresAt: now + 60_000,
                senderAccount: accounts[1]!,
                ownerAccount: accounts[0]!,
                sessionId,
                sessionControl: {
                    version: 1,
                    type: "message",
                    epoch: 1n,
                    content: "application",
                    coveredDevices: recipients(devices[0]!, devices[1]!),
                },
            }),
        );
        expect(memberSend.status).toBe(403);
        expect(await memberSend.json()).toEqual({ error: "session_unauthorized" });

        const nonMemberSend = await publish(
            fanout,
            signedDelivery(deviceSecrets[2]!, [], {
                id: 138,
                now,
                expiresAt: now + 60_000,
                senderAccount: accounts[2]!,
                ownerAccount: accounts[0]!,
                sessionId,
                sessionControl: {
                    version: 1,
                    type: "message",
                    epoch: 1n,
                    content: "protocol",
                    coveredDevices: recipients(devices[0]!, devices[1]!),
                },
            }),
        );
        expect(nonMemberSend.status).toBe(403);

        const unexplainedCommit = await publish(
            fanout,
            signedDelivery(deviceSecrets[0]!, [], {
                id: 139,
                now,
                expiresAt: now + 60_000,
                senderAccount: accounts[0]!,
                ownerAccount: accounts[0]!,
                sessionId,
                sessionControl: {
                    version: 1,
                    type: "commit",
                    epoch: 1n,
                    members: recipients(accounts[0]!, accounts[1]!, accounts[2]!),
                    roles,
                    changes: [],
                    coveredDevices: recipients(devices[0]!, devices[1]!, devices[2]!),
                },
            }),
        );
        expect(unexplainedCommit.status).toBe(403);
        expect(await unexplainedCommit.json()).toEqual({ error: "session_unauthorized" });
    });

    test("self-registers a device, reads its roster, and queues the notification", async () => {
        const now = Date.now();
        const accountSecret = secret(140);
        const account = identity(accountSecret);
        const device = identity(secret(141));
        const inboxes = new InboxNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        expect((await registerDevice(fanout, accountSecret, device, now, 140)).status).toBe(200);
        const lookup = await fanout.fetch(
            internalRequest("/v2/roster/read", {
                version: 1,
                accountKey: encodeBase64Url(account),
            }),
        );
        expect(lookup.status).toBe(200);
        expect(await lookup.json()).toMatchObject({
            roster: {
                revision: 1,
                devices: [{ deviceKey: encodeBase64Url(device), resetGeneration: 0 }],
            },
        });
        await fanout.alarm();
        expect(
            (
                await inboxes.states
                    .get(encodeBase64Url(device))!
                    .storage.list({ prefix: "inbox:event:" })
            ).size,
        ).toBe(1);
    });

    test("rotates, claims, spends, and falls back to a last-resort directory prekey", async () => {
        const now = Date.now();
        const accountSecret = secret(142);
        const account = identity(accountSecret);
        const deviceSecret = secret(143);
        const device = identity(deviceSecret);
        const inboxes = new InboxNamespace();
        const tokenSecret = new Uint8Array(32).fill(9);
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(tokenSecret),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        expect((await registerDevice(fanout, accountSecret, device, now, 142)).status).toBe(200);
        const reference = new Uint8Array(32).fill(144);
        const spent = signedDelivery(deviceSecret, recipients(device), {
            id: 144,
            now,
            expiresAt: now + 60_000,
            senderAccount: account,
            ciphertext: bytes({
                version: 1,
                type: "directory_prekey_spent",
                reference: encodeBase64Url(reference),
            }),
        });
        const upload = signedDelivery(accountSecret, [], {
            id: 145,
            now,
            expiresAt: now + 60_000,
            ciphertext: bytes({
                version: 1,
                type: "directory_prekey_upload",
                mode: "rotate",
                deviceKey: encodeBase64Url(device),
                resetGeneration: 0,
                oneTimePrekeys: [
                    {
                        reference: encodeBase64Url(reference),
                        keyPackage: encodeBase64Url(new Uint8Array([1, 4, 4])),
                        expiresAt: now + 50_000,
                        spentNotification: signedDeliveryToJson(spent),
                    },
                ],
                lastResort: {
                    reference: encodeBase64Url(new Uint8Array(32).fill(145)),
                    keyPackage: encodeBase64Url(new Uint8Array([1, 4, 5])),
                    expiresAt: now + 60_000,
                },
            }),
        });
        const uploaded = await fanout.fetch(
            internalRequest("/v2/directory/upload", {
                delivery: signedDeliveryToJson(upload),
            }),
        );
        expect(uploaded.status).toBe(200);
        const issuer = new LocalDirectoryTicketIssuer({
            issuer: "murmur-cloudflare-directory",
            secretKey: deriveCloudflareDirectoryTicketSecret(encodeBase64Url(tokenSecret)),
        });
        const claim = async (ticketId: number): Promise<Response> =>
            fanout.fetch(
                internalRequest("/v2/directory/claim", {
                    version: 1,
                    accountKey: encodeBase64Url(account),
                    ticket: encodeBase64Url(
                        issuer.issue({
                            expiresAt: now + 60_000,
                            claimBudget: 1,
                            ticketId: new Uint8Array(32).fill(ticketId),
                        }),
                    ),
                }),
            );
        const first = await claim(146);
        expect(first.status).toBe(200);
        expect(await first.json()).toMatchObject({ devices: [{ source: "one_time" }] });
        await fanout.alarm();
        const queued = await inboxes.states
            .get(encodeBase64Url(device))!
            .storage.list<{ readonly delivery: { readonly id: string } }>({
                prefix: "inbox:event:",
            });
        expect([...queued.values()].some((entry) => entry.delivery.id === spent.id)).toBe(true);
        const second = await claim(147);
        expect(second.status).toBe(200);
        expect(await second.json()).toMatchObject({ devices: [{ source: "last_resort" }] });
    });

    test("purges account control state first and retries each inbox cascade", async () => {
        const now = Date.now();
        const accountSecret = secret(148);
        const account = identity(accountSecret);
        const device = identity(secret(149));
        const inboxes = new InboxNamespace();
        const environment: MurmurCloudflareEnvironment = {
            MURMUR_INBOXES: inboxes,
            MURMUR_FANOUT: unusedNamespace,
            MURMUR_RELAY_TOKEN_SECRET: encodeBase64Url(new Uint8Array(32).fill(9)),
            MURMUR_RELAY_ENDPOINT: "wss://relay.test/v2/connect",
        };
        inboxes.setEnvironment(environment);
        const fanout = new MurmurFanoutDurableObject(new MemoryState(), environment);
        expect((await registerDevice(fanout, accountSecret, device, now, 148)).status).toBe(200);
        await fanout.alarm();
        const deviceName = encodeBase64Url(device);
        expect(
            (await inboxes.states.get(deviceName)!.storage.list({ prefix: "inbox:event:" })).size,
        ).toBe(1);
        const deletion = signedDelivery(accountSecret, [], {
            id: 149,
            now,
            expiresAt: now + 60_000,
            ciphertext: bytes({ version: 1, type: "delete_account" }),
        });
        const deleted = await fanout.fetch(
            internalRequest("/v2/delete-account", {
                delivery: signedDeliveryToJson(deletion),
            }),
        );
        expect(deleted.status).toBe(200);
        const lookup = await fanout.fetch(
            internalRequest("/v2/roster/read", {
                version: 1,
                accountKey: encodeBase64Url(account),
            }),
        );
        expect(await lookup.json()).toEqual({ roster: null });

        inboxes.failNameOnce = deviceName;
        await fanout.alarm();
        expect(
            (await inboxes.states.get(deviceName)!.storage.list({ prefix: "inbox:event:" })).size,
        ).toBe(1);
        await fanout.alarm();
        expect((await inboxes.states.get(deviceName)!.storage.list()).size).toBe(0);
    });

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
