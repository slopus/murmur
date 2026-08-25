import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    DeliveryTransportError,
    HttpDeliveryTransport,
    type DeliveryFetch,
    type DeliveryPublishOutcome,
    type DeliveryTransport,
    type InboxPage,
    type SignedDelivery,
    type SignedInboxAck,
    type SignedInboxRead,
} from "../../delivery/index.js";
import { MemoryMurmurStore, type MurmurStore } from "../../storage/index.js";
import {
    MurmurClient,
    type MurmurSession,
    type MurmurSessionPolicies,
    type MurmurUpdate,
} from "../../sessions/index.js";
import {
    decodeSessionRoles,
    encodeSessionRoles,
    type SessionRoles,
} from "../../sessions/impl/sessionFrames.js";
import {
    decodeSessionRecord,
    encodeSessionRecord,
    type SessionRecord,
} from "../../sessions/impl/sessionRecords.js";
import {
    canonicalJsonBytes,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";

const NOW = 1_700_000_000_000;
const SESSION_STATE_PREFIX = "murmur/session-states/";
const SESSION_INTENT_PREFIX = "murmur/session-intents/";
const DELIVERY_STATE_KEYS = ["murmur/delivery/cursor", "murmur/delivery/continuity"] as const;
const PREVIOUS_EPOCH_GRACE_MILLISECONDS = 5 * 60_000;

interface Actor {
    readonly name: "alice" | "bob" | "carol" | "dave" | "erin";
    readonly store: MemoryMurmurStore;
    readonly gate: CommitGateTransport;
    client: MurmurClient;
}

interface RoleFixture {
    readonly relay: RelayService;
    readonly base: HttpDeliveryTransport;
    readonly actors: readonly Actor[];
    readonly alice: Actor;
    readonly bob: Actor;
    readonly carol: Actor;
    readonly dave: Actor;
    readonly erin: Actor;
    readonly sessionId: Uint8Array;
    readonly now: { value: number };
    close(): Promise<void>;
}

interface AdmissionRow {
    readonly name: string;
    readonly actor: Actor;
    readonly allowed: boolean;
    readonly operation: () => Promise<void>;
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "role-policy-chaos",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

class CommitGateTransport implements DeliveryTransport {
    readonly #delegate: DeliveryTransport;
    readonly published: SignedDelivery[] = [];
    blocked = false;

    constructor(delegate: DeliveryTransport) {
        this.#delegate = delegate;
    }

    async publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome> {
        if (delivery.ciphertext[0] === 3) this.published.push(cloneDelivery(delivery));
        if (this.blocked && delivery.ciphertext[0] === 3) {
            throw new DeliveryTransportError(429, "role_commit_blocked");
        }
        return this.#delegate.publish(delivery, signal);
    }

    async read(request: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        return this.#delegate.read(request, signal);
    }

    async acknowledge(
        request: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<{ readonly removed: number }> {
        return this.#delegate.acknowledge(request, signal);
    }
}

function cloneDelivery(delivery: SignedDelivery): SignedDelivery {
    return {
        version: 1,
        id: delivery.id,
        sender: delivery.sender.slice(),
        recipients: delivery.recipients.map((recipient) => recipient.slice()),
        createdAt: delivery.createdAt,
        expiresAt: delivery.expiresAt,
        ciphertext: delivery.ciphertext.slice(),
        signature: delivery.signature.slice(),
    };
}

async function openActor(
    name: Actor["name"],
    base: DeliveryTransport,
    now: () => number,
    store: MemoryMurmurStore = new MemoryMurmurStore(),
): Promise<Actor> {
    const gate = new CommitGateTransport(base);
    return {
        name,
        store,
        gate,
        client: await MurmurClient.open({ transport: gate, store, now }),
    };
}

async function createRoleFixture(policies: MurmurSessionPolicies): Promise<RoleFixture> {
    const now = { value: NOW };
    const relay = new RelayService(
        new SqliteRelayStore(":memory:"),
        {},
        undefined,
        () => now.value,
    );
    const base = new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch(relay) });
    const alice = await openActor("alice", base, () => now.value);
    const bob = await openActor("bob", base, () => now.value);
    const carol = await openActor("carol", base, () => now.value);
    const dave = await openActor("dave", base, () => now.value);
    const erin = await openActor("erin", base, () => now.value);
    const actors = [alice, bob, carol, dave, erin] as const;
    try {
        const session = await alice.client.createSession({
            descriptor: utf8Encode("role-policy chaos"),
            adminsAssignAdmins: policies.adminsAssignAdmins,
            anyoneCanAddMembers: policies.anyoneCanAddMembers,
            members: [
                await bob.client.discovery(),
                await carol.client.discovery(),
                await dave.client.discovery(),
            ],
        });
        await synchronize([alice, bob, carol, dave], 2);
        for (const actor of [bob, carol, dave]) {
            const current = await actor.client.session(session.id);
            if (current?.status === "pending") await actor.client.activateSession(session.id);
        }
        await alice.client.grantAdmin(session.id, bob.client.accountKey);
        await synchronize([alice, bob, carol, dave], 3);
        expect(await alice.client.session(session.id)).toMatchObject({
            owner: alice.client.accountKey,
            admins: expect.arrayContaining([alice.client.accountKey, bob.client.accountKey]),
            policies,
        });
        return {
            relay,
            base,
            actors,
            alice,
            bob,
            carol,
            dave,
            erin,
            sessionId: session.id,
            now,
            close: async (): Promise<void> => {
                for (const actor of actors) actor.client.close();
                await relay.close();
            },
        };
    } catch (error: unknown) {
        for (const actor of actors) actor.client.close();
        await relay.close();
        throw error;
    }
}

async function synchronize(actors: readonly Actor[], rounds: number): Promise<void> {
    for (let round = 0; round < rounds; round += 1) {
        for (const actor of actors) {
            await actor.client.synchronize({ waitMilliseconds: 0 });
            await new Promise<void>((resolve) => setTimeout(resolve, 0));
        }
    }
}

async function consume(actor: Actor): Promise<readonly MurmurUpdate[]> {
    const updates: MurmurUpdate[] = [];
    await actor.client.synchronize(
        { waitMilliseconds: 0 },
        {
            onUpdates: async (batch) => {
                updates.push(...batch);
            },
        },
    );
    return updates;
}

async function intentKeys(store: MurmurStore): Promise<readonly string[]> {
    const page = await store.scan(SESSION_INTENT_PREFIX, { limit: 256 });
    try {
        return [...page.keys()];
    } finally {
        for (const value of page.values()) zeroBytes(value);
    }
}

async function clearIntents(store: MurmurStore): Promise<void> {
    const keys = await intentKeys(store);
    await store.transaction(async (transaction) => {
        for (const key of keys) await transaction.delete(key);
    });
}

async function assertAdmission(row: AdmissionRow): Promise<void> {
    expect(await intentKeys(row.actor.store), row.name).toEqual([]);
    if (row.allowed) {
        await row.operation();
        expect(await intentKeys(row.actor.store), row.name).toHaveLength(1);
        await clearIntents(row.actor.store);
    } else {
        await expect(row.operation(), row.name).rejects.toThrow();
        expect(await intentKeys(row.actor.store), row.name).toEqual([]);
    }
}

async function rewriteRoles(
    actor: Actor,
    sessionId: Uint8Array,
    mutate: (roles: SessionRoles) => SessionRoles,
): Promise<void> {
    const key = `${SESSION_STATE_PREFIX}${encodeBase64Url(sessionId)}`;
    const bytes = await actor.store.get(key);
    if (bytes === undefined) throw new Error("Missing role-chaos session state");
    const record = decodeSessionRecord(bytes);
    try {
        await actor.store.set(key, encodeSessionRecord({ ...record, roles: mutate(record.roles) }));
    } finally {
        zeroRecord(record);
        zeroBytes(bytes);
    }
}

function zeroRecord(record: SessionRecord): void {
    zeroBytes(record.epoch);
    if (record.previousEpoch !== undefined) zeroBytes(record.previousEpoch);
    zeroBytes(record.roles.owner);
    for (const admin of record.roles.admins) zeroBytes(admin);
    for (const generation of record.removalGenerations) zeroBytes(generation.account);
}

function roleSnapshot(session: MurmurSession): object {
    return {
        members: session.members.map(encodeBase64Url).sort(),
        owner: encodeBase64Url(session.owner),
        admins: session.admins.map(encodeBase64Url).sort(),
        policies: session.policies,
    };
}

async function requireSession(actor: Actor, sessionId: Uint8Array): Promise<MurmurSession> {
    const session = await actor.client.session(sessionId);
    if (session === undefined) throw new Error(`${actor.name} is missing the role-chaos session`);
    return session;
}

async function cloneMemoryStore(source: MurmurStore): Promise<MemoryMurmurStore> {
    const target = new MemoryMurmurStore();
    let after: string | undefined;
    for (;;) {
        const page = await source.scan("", {
            ...(after === undefined ? {} : { after }),
            limit: 256,
        });
        try {
            await target.transaction(async (transaction) => {
                for (const [key, value] of page) {
                    after = key;
                    await transaction.set(key, value);
                }
            });
        } finally {
            for (const value of page.values()) zeroBytes(value);
        }
        if (page.size < 256) return target;
    }
}

async function copyDeliveryProgress(source: MurmurStore, target: MurmurStore): Promise<void> {
    for (const key of DELIVERY_STATE_KEYS) {
        const value = await source.get(key);
        try {
            if (value === undefined) await target.delete(key);
            else await target.set(key, value);
        } finally {
            if (value !== undefined) zeroBytes(value);
        }
    }
}

describe("role, policy, and private-roster session races", () => {
    test("role truth table admits exactly the authorized local intents under all four policies", async () => {
        for (const adminsAssignAdmins of [false, true]) {
            for (const anyoneCanAddMembers of [false, true]) {
                const fixture = await createRoleFixture({
                    adminsAssignAdmins,
                    anyoneCanAddMembers,
                });
                try {
                    const id = fixture.sessionId;
                    const a = fixture.alice.client;
                    const b = fixture.bob.client;
                    const c = fixture.carol.client;
                    const d = fixture.dave.client;
                    const rows: AdmissionRow[] = [
                        {
                            name: "owner grants a member admin",
                            actor: fixture.alice,
                            allowed: true,
                            operation: () => a.grantAdmin(id, d.accountKey),
                        },
                        {
                            name: "admin grant follows adminsAssignAdmins",
                            actor: fixture.bob,
                            allowed: adminsAssignAdmins,
                            operation: () => b.grantAdmin(id, d.accountKey),
                        },
                        {
                            name: "plain member never grants admin",
                            actor: fixture.carol,
                            allowed: false,
                            operation: () => c.grantAdmin(id, d.accountKey),
                        },
                        {
                            name: "owner revokes a non-owner admin",
                            actor: fixture.alice,
                            allowed: true,
                            operation: () => a.revokeAdmin(id, b.accountKey),
                        },
                        {
                            name: "admin never revokes admin",
                            actor: fixture.bob,
                            allowed: false,
                            operation: () => b.revokeAdmin(id, b.accountKey),
                        },
                        {
                            name: "member never revokes admin",
                            actor: fixture.carol,
                            allowed: false,
                            operation: () => c.revokeAdmin(id, b.accountKey),
                        },
                        {
                            name: "owner updates policy",
                            actor: fixture.alice,
                            allowed: true,
                            operation: () =>
                                a.setPolicies(id, {
                                    adminsAssignAdmins: !adminsAssignAdmins,
                                    anyoneCanAddMembers: !anyoneCanAddMembers,
                                }),
                        },
                        {
                            name: "admin never updates policy",
                            actor: fixture.bob,
                            allowed: false,
                            operation: () =>
                                b.setPolicies(id, {
                                    adminsAssignAdmins,
                                    anyoneCanAddMembers,
                                }),
                        },
                        {
                            name: "member never updates policy",
                            actor: fixture.carol,
                            allowed: false,
                            operation: () =>
                                c.setPolicies(id, {
                                    adminsAssignAdmins,
                                    anyoneCanAddMembers,
                                }),
                        },
                        {
                            name: "owner adds",
                            actor: fixture.alice,
                            allowed: true,
                            operation: async () =>
                                a.addMember(id, await fixture.erin.client.discovery()),
                        },
                        {
                            name: "admin adds",
                            actor: fixture.bob,
                            allowed: true,
                            operation: async () =>
                                b.addMember(id, await fixture.erin.client.discovery()),
                        },
                        {
                            name: "member add follows anyoneCanAddMembers",
                            actor: fixture.carol,
                            allowed: anyoneCanAddMembers,
                            operation: async () =>
                                c.addMember(id, await fixture.erin.client.discovery()),
                        },
                        {
                            name: "admin removes another member",
                            actor: fixture.bob,
                            allowed: true,
                            operation: () => b.removeMember(id, d.accountKey),
                        },
                        {
                            name: "member cannot remove another member",
                            actor: fixture.carol,
                            allowed: false,
                            operation: () => c.removeMember(id, d.accountKey),
                        },
                        {
                            name: "member removes self",
                            actor: fixture.carol,
                            allowed: true,
                            operation: () => c.removeMember(id, c.accountKey),
                        },
                        {
                            name: "owner cannot remove self",
                            actor: fixture.alice,
                            allowed: false,
                            operation: () => a.removeMember(id, a.accountKey),
                        },
                        {
                            name: "admin cannot remove owner",
                            actor: fixture.bob,
                            allowed: false,
                            operation: () => b.removeMember(id, a.accountKey),
                        },
                        {
                            name: "owner cannot demote self",
                            actor: fixture.alice,
                            allowed: false,
                            operation: () => a.revokeAdmin(id, a.accountKey),
                        },
                        {
                            name: "owner cannot leave",
                            actor: fixture.alice,
                            allowed: false,
                            operation: () => a.leave(id),
                        },
                        {
                            name: "member may leave",
                            actor: fixture.carol,
                            allowed: true,
                            operation: () => c.leave(id),
                        },
                    ];
                    for (const row of rows) await assertAdmission(row);

                    if (adminsAssignAdmins) {
                        await a.grantAdmin(id, c.accountKey);
                        await synchronize(
                            [fixture.alice, fixture.bob, fixture.carol, fixture.dave],
                            3,
                        );
                        await assertAdmission({
                            name: "promoted member grants when policy permits",
                            actor: fixture.carol,
                            allowed: true,
                            operation: () => c.grantAdmin(id, d.accountKey),
                        });
                    }
                } finally {
                    await fixture.close();
                }
            }
        }
    }, 120_000);

    test("ROLE-01/08 forged remote controls and malformed role encodings fail closed", async () => {
        const owner = new Uint8Array(32).fill(1);
        const first = new Uint8Array(32).fill(2);
        const second = new Uint8Array(32).fill(3);
        const canonical = [encodeBase64Url(first), encodeBase64Url(second)].sort();
        const malformed = [
            canonicalJsonBytes({
                owner: encodeBase64Url(owner),
                admins: [...canonical].reverse(),
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
            }),
            canonicalJsonBytes({
                owner: encodeBase64Url(owner),
                admins: [canonical[0]!, canonical[0]!],
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
            }),
            canonicalJsonBytes({
                owner: encodeBase64Url(owner),
                admins: [encodeBase64Url(owner)],
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
            }),
            canonicalJsonBytes({
                owner: encodeBase64Url(owner),
                admins: [],
                adminsAssignAdmins: 1,
                anyoneCanAddMembers: false,
            }),
            new Uint8Array([
                ...encodeSessionRoles({
                    owner,
                    admins: [],
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                }),
                0,
            ]),
        ];
        for (const bytes of malformed) expect(() => decodeSessionRoles(bytes)).toThrow();

        const attacks = ["member-add", "admin-grant", "admin-revoke", "admin-policy"] as const;
        for (const attack of attacks) {
            const fixture = await createRoleFixture({
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
            });
            try {
                const before = roleSnapshot(await requireSession(fixture.alice, fixture.sessionId));
                const attacker = attack === "member-add" ? fixture.carol : fixture.bob;
                if (attack === "member-add") {
                    await rewriteRoles(attacker, fixture.sessionId, (roles) => ({
                        ...roles,
                        anyoneCanAddMembers: true,
                    }));
                    await attacker.client.addMember(
                        fixture.sessionId,
                        await fixture.erin.client.discovery(),
                    );
                } else if (attack === "admin-grant") {
                    await rewriteRoles(attacker, fixture.sessionId, (roles) => ({
                        ...roles,
                        adminsAssignAdmins: true,
                    }));
                    await attacker.client.grantAdmin(
                        fixture.sessionId,
                        fixture.dave.client.accountKey,
                    );
                } else {
                    await rewriteRoles(attacker, fixture.sessionId, (roles) => ({
                        ...roles,
                        owner: attacker.client.accountKey,
                        admins: [fixture.alice.client.accountKey],
                    }));
                    if (attack === "admin-revoke") {
                        await attacker.client.revokeAdmin(
                            fixture.sessionId,
                            fixture.alice.client.accountKey,
                        );
                    } else {
                        await attacker.client.setPolicies(fixture.sessionId, {
                            adminsAssignAdmins: true,
                            anyoneCanAddMembers: true,
                        });
                    }
                }
                await attacker.client.synchronize({ waitMilliseconds: 0 });
                const honest = [fixture.alice, fixture.dave];
                await synchronize(honest, 2);
                for (const actor of honest) {
                    expect(roleSnapshot(await requireSession(actor, fixture.sessionId))).toEqual(
                        before,
                    );
                    expect(await actor.client.issues()).toEqual(
                        expect.arrayContaining([
                            expect.objectContaining({ code: "unauthorized_commit" }),
                        ]),
                    );
                }

                await fixture.alice.client.send(
                    fixture.sessionId,
                    utf8Encode(`valid-after-${attack}`),
                );
                await fixture.alice.client.synchronize({ waitMilliseconds: 0 });
                const updates = await consume(fixture.dave);
                expect(updates.map((update) => utf8Decode(update.bytes))).toContain(
                    `valid-after-${attack}`,
                );
            } finally {
                await fixture.close();
            }
        }
    }, 120_000);

    test("ROLE-02/03 grant, revoke, and policy candidates authorize against their parent epoch", async () => {
        for (const winner of ["grant", "policy"] as const) {
            const fixture = await createRoleFixture({
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
            });
            try {
                fixture.bob.gate.blocked = winner === "policy";
                await fixture.bob.client.grantAdmin(
                    fixture.sessionId,
                    fixture.carol.client.accountKey,
                );
                if (winner === "grant") {
                    await synchronize([fixture.bob, fixture.alice, fixture.carol, fixture.dave], 2);
                } else {
                    await fixture.bob.client.synchronize({ waitMilliseconds: 0 });
                }
                await fixture.alice.client.setPolicies(fixture.sessionId, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                });
                await synchronize([fixture.alice, fixture.carol, fixture.dave], 3);
                fixture.bob.gate.blocked = false;
                await synchronize([fixture.bob, fixture.alice, fixture.carol, fixture.dave], 5);
                const final = await requireSession(fixture.alice, fixture.sessionId);
                expect(final.policies.adminsAssignAdmins).toBe(false);
                expect(
                    final.admins.filter((admin) =>
                        equalBytes(admin, fixture.carol.client.accountKey),
                    ),
                ).toHaveLength(winner === "grant" ? 1 : 0);
                expect(final.admins.filter((admin) => equalBytes(admin, final.owner))).toHaveLength(
                    1,
                );
            } finally {
                await fixture.close();
            }
        }

        const duplicate = await createRoleFixture({
            adminsAssignAdmins: true,
            anyoneCanAddMembers: false,
        });
        try {
            duplicate.bob.gate.blocked = true;
            await duplicate.bob.client.grantAdmin(
                duplicate.sessionId,
                duplicate.carol.client.accountKey,
            );
            await duplicate.bob.client.synchronize({ waitMilliseconds: 0 });
            await duplicate.alice.client.grantAdmin(
                duplicate.sessionId,
                duplicate.carol.client.accountKey,
            );
            await synchronize([duplicate.alice, duplicate.carol, duplicate.dave], 3);
            duplicate.bob.gate.blocked = false;
            await synchronize([duplicate.bob, duplicate.alice, duplicate.carol, duplicate.dave], 5);
            const final = await requireSession(duplicate.alice, duplicate.sessionId);
            expect(
                final.admins.filter((admin) =>
                    equalBytes(admin, duplicate.carol.client.accountKey),
                ),
            ).toHaveLength(1);
        } finally {
            await duplicate.close();
        }

        for (const winner of ["bob-grant", "alice-revoke"] as const) {
            const fixture = await createRoleFixture({
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
            });
            try {
                fixture.bob.gate.blocked = winner === "alice-revoke";
                await fixture.bob.client.grantAdmin(
                    fixture.sessionId,
                    fixture.carol.client.accountKey,
                );
                if (winner === "bob-grant") {
                    await synchronize([fixture.bob, fixture.alice, fixture.carol, fixture.dave], 2);
                } else {
                    await fixture.bob.client.synchronize({ waitMilliseconds: 0 });
                }
                await fixture.alice.client.revokeAdmin(
                    fixture.sessionId,
                    fixture.bob.client.accountKey,
                );
                await synchronize([fixture.alice, fixture.carol, fixture.dave], 3);
                fixture.bob.gate.blocked = false;
                await synchronize([fixture.bob, fixture.alice, fixture.carol, fixture.dave], 5);
                const final = await requireSession(fixture.alice, fixture.sessionId);
                expect(
                    final.admins.some((admin) => equalBytes(admin, fixture.bob.client.accountKey)),
                ).toBe(false);
                expect(
                    final.admins.some((admin) =>
                        equalBytes(admin, fixture.carol.client.accountKey),
                    ),
                ).toBe(winner === "bob-grant");
                if (winner === "bob-grant") {
                    await fixture.alice.client.revokeAdmin(
                        fixture.sessionId,
                        fixture.carol.client.accountKey,
                    );
                    await synchronize([fixture.alice, fixture.carol, fixture.dave], 3);
                    expect(
                        (await requireSession(fixture.alice, fixture.sessionId)).admins.some(
                            (admin) => equalBytes(admin, fixture.carol.client.accountKey),
                        ),
                    ).toBe(false);
                }
            } finally {
                await fixture.close();
            }
        }
    }, 120_000);

    test("ROLE-04/05 policy-versus-Add and self-leave races cannot create zombie members", async () => {
        for (const winner of ["add", "policy"] as const) {
            const fixture = await createRoleFixture({
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
            });
            try {
                fixture.carol.gate.blocked = winner === "policy";
                await fixture.carol.client.addMember(
                    fixture.sessionId,
                    await fixture.erin.client.discovery(),
                );
                if (winner === "add") {
                    await synchronize([fixture.carol, fixture.alice, fixture.bob, fixture.dave], 3);
                } else {
                    await fixture.carol.client.synchronize({ waitMilliseconds: 0 });
                }
                await fixture.alice.client.setPolicies(fixture.sessionId, {
                    adminsAssignAdmins: false,
                    anyoneCanAddMembers: false,
                });
                await synchronize([fixture.alice, fixture.bob, fixture.dave], 3);
                fixture.carol.gate.blocked = false;
                await synchronize([fixture.carol, fixture.alice, fixture.bob, fixture.dave], 5);
                const final = await requireSession(fixture.alice, fixture.sessionId);
                expect(final.policies.anyoneCanAddMembers).toBe(false);
                expect(
                    final.members.some((member) =>
                        equalBytes(member, fixture.erin.client.accountKey),
                    ),
                ).toBe(winner === "add");
            } finally {
                await fixture.close();
            }
        }

        const crashed = await createRoleFixture({
            adminsAssignAdmins: false,
            anyoneCanAddMembers: true,
        });
        try {
            crashed.carol.gate.blocked = true;
            await crashed.carol.client.addMember(
                crashed.sessionId,
                await crashed.erin.client.discovery(),
            );
            await crashed.carol.client.synchronize({ waitMilliseconds: 0 });
            await crashed.alice.client.setPolicies(crashed.sessionId, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
            });
            await synchronize([crashed.alice, crashed.bob, crashed.dave], 3);
            crashed.carol.client.close();
            crashed.carol.gate.blocked = false;
            crashed.carol.client = await MurmurClient.open({
                transport: crashed.carol.gate,
                store: crashed.carol.store,
                now: () => crashed.now.value,
            });
            await synchronize([crashed.carol, crashed.alice, crashed.bob, crashed.dave], 5);
            const final = await requireSession(crashed.alice, crashed.sessionId);
            expect(final.policies.anyoneCanAddMembers).toBe(false);
            expect(
                final.members.some((member) => equalBytes(member, crashed.erin.client.accountKey)),
            ).toBe(false);
        } finally {
            await crashed.close();
        }

        for (const ownerAction of ["grant", "remove"] as const) {
            const fixture = await createRoleFixture({
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
            });
            try {
                await fixture.carol.client.leave(fixture.sessionId);
                await fixture.carol.client.synchronize({ waitMilliseconds: 0 });
                if (ownerAction === "grant") {
                    await fixture.alice.client.grantAdmin(
                        fixture.sessionId,
                        fixture.carol.client.accountKey,
                    );
                } else {
                    await fixture.alice.client.removeMember(
                        fixture.sessionId,
                        fixture.carol.client.accountKey,
                    );
                }
                await synchronize([fixture.alice, fixture.bob, fixture.dave, fixture.carol], 6);
                const final = await requireSession(fixture.alice, fixture.sessionId);
                expect(
                    final.members.some((member) =>
                        equalBytes(member, fixture.carol.client.accountKey),
                    ),
                ).toBe(false);
                expect(
                    final.admins.some((admin) =>
                        equalBytes(admin, fixture.carol.client.accountKey),
                    ),
                ).toBe(false);
                expect((await fixture.alice.client.issues()).length).toBeLessThanOrEqual(1);
            } finally {
                await fixture.close();
            }
        }
    }, 120_000);

    test("ROLE-06 removed-admin old-epoch application and control traffic never restores authority", async () => {
        const fixture = await createRoleFixture({
            adminsAssignAdmins: true,
            anyoneCanAddMembers: false,
        });
        try {
            const withinStore = await cloneMemoryStore(fixture.bob.store);
            const outsideStore = await cloneMemoryStore(fixture.bob.store);
            const controlStore = await cloneMemoryStore(fixture.bob.store);
            await fixture.alice.client.removeMember(
                fixture.sessionId,
                fixture.bob.client.accountKey,
            );
            await synchronize([fixture.alice, fixture.carol, fixture.dave], 4);
            const removed = roleSnapshot(await requireSession(fixture.alice, fixture.sessionId));

            const oldWithin = await openActor(
                "bob",
                fixture.base,
                () => fixture.now.value,
                withinStore,
            );
            const oldOutside = await openActor(
                "bob",
                fixture.base,
                () => fixture.now.value,
                outsideStore,
            );
            const oldControl = await openActor(
                "bob",
                fixture.base,
                () => fixture.now.value,
                controlStore,
            );
            try {
                await oldWithin.client.send(
                    fixture.sessionId,
                    utf8Encode("old epoch within grace"),
                );
                await oldWithin.client.synchronize({ waitMilliseconds: 0 });
                await synchronize([fixture.alice, fixture.carol, fixture.dave], 2);
                const within = await consume(fixture.dave);
                expect(within.length).toBeLessThanOrEqual(1);

                await copyDeliveryProgress(oldWithin.store, oldOutside.store);
                fixture.now.value += PREVIOUS_EPOCH_GRACE_MILLISECONDS + 1;
                await oldOutside.client.send(
                    fixture.sessionId,
                    utf8Encode("old epoch outside grace"),
                );
                await oldOutside.client.synchronize({ waitMilliseconds: 0 });
                await synchronize([fixture.alice, fixture.carol, fixture.dave], 2);
                const outside = await consume(fixture.dave);
                expect(outside.map((update) => utf8Decode(update.bytes))).not.toContain(
                    "old epoch outside grace",
                );

                await copyDeliveryProgress(oldOutside.store, oldControl.store);
                await oldControl.client.grantAdmin(
                    fixture.sessionId,
                    fixture.carol.client.accountKey,
                );
                await oldControl.client.synchronize({ waitMilliseconds: 0 });
                await synchronize([fixture.alice, fixture.carol, fixture.dave], 3);
                for (const actor of [fixture.alice, fixture.carol, fixture.dave]) {
                    expect(roleSnapshot(await requireSession(actor, fixture.sessionId))).toEqual(
                        removed,
                    );
                }
                const captured = oldControl.gate.published.at(-1);
                if (captured === undefined) throw new Error("Old admin Commit was not captured");
                const replay = await fixture.base.publish(captured);
                expect(replay.duplicate).toBe(true);
                await synchronize([fixture.alice, fixture.carol, fixture.dave], 2);
                expect(
                    roleSnapshot(await requireSession(fixture.alice, fixture.sessionId)),
                ).toEqual(removed);
            } finally {
                oldWithin.client.close();
                oldOutside.client.close();
                oldControl.client.close();
            }
        } finally {
            await fixture.close();
        }
    }, 120_000);

    test("ROLE-07 an admin account spans two devices and loses authority account-wide", async () => {
        const fixture = await createRoleFixture({
            adminsAssignAdmins: true,
            anyoneCanAddMembers: false,
        });
        const bobSecond = await openActor("bob", fixture.base, () => fixture.now.value);
        try {
            const request = await bobSecond.client.linkDevice();
            await fixture.bob.client.authorizeDevice(request);
            await synchronize([bobSecond], 2);
            expect(bobSecond.client.accountKey).toEqual(fixture.bob.client.accountKey);
            await synchronize(
                [fixture.alice, fixture.bob, bobSecond, fixture.carol, fixture.dave],
                8,
            );
            const secondSession = await bobSecond.client.session(fixture.sessionId);
            if (secondSession?.status === "pending") {
                await bobSecond.client.activateSession(fixture.sessionId);
                await synchronize(
                    [fixture.alice, fixture.bob, bobSecond, fixture.carol, fixture.dave],
                    3,
                );
            }

            for (const actor of [fixture.alice, fixture.bob, bobSecond]) {
                const session = await requireSession(actor, fixture.sessionId);
                expect(
                    session.admins.filter((admin) =>
                        equalBytes(admin, fixture.bob.client.accountKey),
                    ),
                ).toHaveLength(1);
            }
            await bobSecond.client.grantAdmin(fixture.sessionId, fixture.carol.client.accountKey);
            await synchronize(
                [bobSecond, fixture.alice, fixture.bob, fixture.carol, fixture.dave],
                4,
            );
            expect(
                (await requireSession(fixture.alice, fixture.sessionId)).admins.some((admin) =>
                    equalBytes(admin, fixture.carol.client.accountKey),
                ),
            ).toBe(true);

            await fixture.bob.client.revokeDevice(bobSecond.client.identity);
            await synchronize([fixture.bob, fixture.alice, fixture.carol, fixture.dave], 8);
            const afterDeviceRevoke = await requireSession(fixture.alice, fixture.sessionId);
            expect(afterDeviceRevoke.members).toContainEqual(fixture.bob.client.accountKey);
            expect(afterDeviceRevoke.admins).toContainEqual(fixture.bob.client.accountKey);

            await fixture.alice.client.revokeAdmin(
                fixture.sessionId,
                fixture.bob.client.accountKey,
            );
            await synchronize([fixture.alice, fixture.bob, fixture.carol, fixture.dave], 4);
            expect(
                (await requireSession(fixture.alice, fixture.sessionId)).admins.some((admin) =>
                    equalBytes(admin, fixture.bob.client.accountKey),
                ),
            ).toBe(false);
            await expect(
                fixture.bob.client.grantAdmin(fixture.sessionId, fixture.dave.client.accountKey),
            ).rejects.toThrow();
        } finally {
            bobSecond.client.close();
            await fixture.close();
        }
    }, 120_000);
});
