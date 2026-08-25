import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    ACCOUNT_CONVERGENCE_PREFIX,
    ACCOUNT_ROSTER_KEY,
    accountConvergenceJobs,
    addDeviceToRoster,
    authorizeDeviceProvisioning,
    completeDeviceProvisioning,
    createDeviceLinkMaterial,
    createInitialDeviceRoster,
    deviceRosterHash,
    isActiveDevice,
    observeDeviceRoster,
    parseDeviceRoster,
    revokeDeviceFromRoster,
    selectDeviceRosterChild,
    serializeDeviceRoster,
    type MurmurDeviceProvisioningEnvelope,
    type MurmurDeviceRoster,
} from "../../accounts/index.js";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    importIdentityKeyPair,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import {
    HttpDeliveryTransport,
    type DeliveryPublishOutcome,
    type DeliveryStreamHooks,
    type DeliveryTransport,
    type InboxPage,
    type SignedDelivery,
    type SignedInboxAck,
    type SignedInboxRead,
} from "../../delivery/index.js";
import { HttpDiscoveryTransport, type DiscoveryFetch } from "../../identity/discovery/index.js";
import { MurmurClient, type MurmurSession, type MurmurUpdate } from "../../sessions/index.js";
import { MemoryMurmurStore, type MurmurStore, type StoreTransaction } from "../../storage/index.js";
import {
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import {
    ChaosCrashError,
    FaultInjectingDeliveryTransport,
    FaultInjectingMurmurStore,
    ManualVirtualClock,
    SeededChaosSchedule,
    SeededRandom,
    settleChaos,
} from "../index.js";

const NOW = 1_700_000_000_000;
const PROVISIONING_TTL = 5 * 60 * 1_000;
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;
const CHAT_DESCRIPTOR = utf8Encode('{"protocol":"chaos.multidevice","version":1}');

function relayFetch(relay: RelayService): DiscoveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "multidevice-chaos",
        maximumRequestsPerMinutePerAddress: 1_000_000,
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
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

class RecordingTransport implements DeliveryTransport {
    readonly published: SignedDelivery[] = [];
    readonly #delegate: DeliveryTransport;
    readonly stream?: NonNullable<DeliveryTransport["stream"]>;

    constructor(delegate: DeliveryTransport) {
        this.#delegate = delegate;
        if (delegate.stream !== undefined) {
            this.stream = (
                request: SignedInboxRead,
                signal?: AbortSignal,
                hooks?: DeliveryStreamHooks,
            ) => delegate.stream!.call(delegate, request, signal, hooks);
        }
    }

    async publish(delivery: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome> {
        this.published.push(cloneDelivery(delivery));
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

interface RealNetwork {
    readonly relay: RelayService;
    readonly fetch: DiscoveryFetch;
    readonly clock: ManualVirtualClock;
}

function realNetwork(): RealNetwork {
    const clock = new ManualVirtualClock(NOW);
    const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () =>
        clock.now(),
    );
    return { relay, fetch: relayFetch(relay), clock };
}

class DeviceNode {
    readonly name: string;
    readonly client: MurmurClient;
    readonly store: MurmurStore;
    readonly recording: RecordingTransport;
    readonly messages: string[] = [];
    readonly added: string[] = [];
    readonly revoked: string[] = [];

    constructor(
        name: string,
        client: MurmurClient,
        store: MurmurStore,
        recording: RecordingTransport,
    ) {
        this.name = name;
        this.client = client;
        this.store = store;
        this.recording = recording;
    }

    async pump(): Promise<void> {
        const lifecycle = {
            onUpdates: async (updates: readonly MurmurUpdate[]): Promise<void> => {
                this.messages.push(...updates.map((update) => utf8Decode(update.bytes)));
            },
            onDeviceAdded: async (
                events: readonly { readonly device: Uint8Array }[],
            ): Promise<void> => {
                this.added.push(...events.map((event) => encodeBase64Url(event.device)));
            },
            onDeviceRevoked: async (
                events: readonly { readonly device: Uint8Array }[],
            ): Promise<void> => {
                this.revoked.push(...events.map((event) => encodeBase64Url(event.device)));
            },
        };
        await this.client.synchronize({ waitMilliseconds: 0 }, lifecycle);
        const sessions = await this.client.sessions();
        for (const session of sessions.sessions) {
            if (session.status === "pending" && equalBytes(session.descriptor, CHAT_DESCRIPTOR)) {
                await this.client.activateSession(session.id);
            }
        }
        await this.client.synchronize({ waitMilliseconds: 0 }, lifecycle);
        // Keep the long integration case observable to Vitest's worker RPC loop.
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }

    close(): void {
        this.client.close();
    }
}

async function openNode(
    name: string,
    network: RealNetwork,
    options: {
        readonly store?: MurmurStore;
        readonly schedule?: SeededChaosSchedule;
    } = {},
): Promise<DeviceNode> {
    const store = options.store ?? new MemoryMurmurStore();
    const recording = new RecordingTransport(
        new HttpDeliveryTransport("https://relay.test", { fetch: network.fetch }),
    );
    const transport = new FaultInjectingDeliveryTransport({
        actor: name,
        delegate: recording,
        schedule: options.schedule ?? new SeededChaosSchedule(0x44455600),
    });
    const client = await MurmurClient.open({
        transport,
        discoveryTransport: new HttpDiscoveryTransport("https://relay.test", {
            fetch: network.fetch,
        }),
        store,
        now: () => network.clock.now(),
    });
    return new DeviceNode(name, client, store, recording);
}

async function pumpAll(nodes: readonly DeviceNode[], rounds: number): Promise<void> {
    for (let round = 0; round < rounds; round += 1) {
        for (const node of nodes) await node.pump();
    }
}

async function settleNodes(
    nodes: readonly DeviceNode[],
    maximumRounds: number = 20,
): Promise<void> {
    await settleChaos({
        maximumRounds,
        unchangedRounds: 2,
        act: async () => {
            for (const node of nodes) await node.pump();
        },
        snapshot: async () => {
            const snapshots: string[] = [];
            for (const node of nodes) {
                const sessions = await node.client.sessions();
                const devices = await node.client.devices();
                snapshots.push(
                    JSON.stringify({
                        name: node.name,
                        sessions: sessions.sessions.map((session) => ({
                            id: encodeBase64Url(session.id),
                            status: session.status,
                            members: session.members.map(encodeBase64Url).sort(),
                            owner: encodeBase64Url(session.owner),
                            admins: session.admins.map(encodeBase64Url).sort(),
                            policies: session.policies,
                        })),
                        devices: devices.map((device) => ({
                            device: encodeBase64Url(device.deviceKey),
                            status: device.status,
                        })),
                        messages: node.messages,
                    }),
                );
            }
            return snapshots;
        },
        equal: (left, right) => JSON.stringify(left) === JSON.stringify(right),
        describe: (state) => state.join(" | "),
    });
}

interface AccountActors {
    readonly alice: IdentityKeyPair;
    readonly a1: IdentityKeyPair;
    readonly a2: IdentityKeyPair;
    readonly a3: IdentityKeyPair;
    readonly bob: IdentityKeyPair;
    readonly b1: IdentityKeyPair;
    readonly b2: IdentityKeyPair;
    readonly carol: IdentityKeyPair;
    readonly c1: IdentityKeyPair;
}

function accountActors(): AccountActors {
    return {
        alice: generateIdentityKeyPair(),
        a1: generateIdentityKeyPair(),
        a2: generateIdentityKeyPair(),
        a3: generateIdentityKeyPair(),
        bob: generateIdentityKeyPair(),
        b1: generateIdentityKeyPair(),
        b2: generateIdentityKeyPair(),
        carol: generateIdentityKeyPair(),
        c1: generateIdentityKeyPair(),
    };
}

function destroyActors(actors: AccountActors): void {
    for (const identity of Object.values(actors)) destroyIdentity(identity);
}

function initialRoster(account: IdentityKeyPair, device: IdentityKeyPair): MurmurDeviceRoster {
    return createInitialDeviceRoster(account, device, NOW, new Uint8Array(16));
}

async function storedRoster(store: MurmurStore): Promise<MurmurDeviceRoster> {
    const bytes = await store.get(ACCOUNT_ROSTER_KEY);
    if (bytes === undefined) throw new Error("Missing stored roster");
    try {
        return parseDeviceRoster(bytes);
    } finally {
        zeroBytes(bytes);
    }
}

async function observe(
    store: MurmurStore,
    ownAccount: Uint8Array,
    eventId: string,
    roster: MurmurDeviceRoster,
    admission?: { readonly device: Uint8Array; readonly keyPackage: Uint8Array },
): Promise<void> {
    await store.transaction((transaction: StoreTransaction) =>
        observeDeviceRoster(
            transaction,
            ownAccount,
            eventId,
            roster.accountKey,
            roster.authorDeviceKey,
            serializeDeviceRoster(roster),
            admission,
        ),
    );
}

function sortedKeys(values: readonly Uint8Array[]): string[] {
    return values.map(encodeBase64Url).sort();
}

function sessionMembers(session: MurmurSession | undefined): string[] {
    if (session === undefined) throw new Error("Missing session");
    return sortedKeys(session.members);
}

function publishedById(node: DeviceNode, id: string): SignedDelivery {
    const delivery = node.recording.published.find((candidate) => candidate.id === id);
    if (delivery === undefined) throw new Error(`${node.name} did not publish ${id}`);
    return delivery;
}

describe("multi-device and provisioning chaos", () => {
    test("DEV-01 enforces exact five-minute and KeyPackage size boundaries", () => {
        const actors = accountActors();
        const roster = initialRoster(actors.alice, actors.a1);
        const maximum = new Uint8Array(MAXIMUM_KEY_PACKAGE_BYTES).fill(7);
        try {
            const below = createDeviceLinkMaterial(
                actors.a2,
                new Uint8Array([1]),
                NOW,
                PROVISIONING_TTL - 1,
            );
            const exact = createDeviceLinkMaterial(actors.a2, maximum, NOW, PROVISIONING_TTL);
            try {
                expect(
                    authorizeDeviceProvisioning({
                        request: below.request,
                        account: actors.alice,
                        authorDevice: actors.a1,
                        roster,
                        now: below.request.expiresAt - 1,
                    }).roster.revision,
                ).toBe(2);
                expect(
                    authorizeDeviceProvisioning({
                        request: exact.request,
                        account: actors.alice,
                        authorDevice: actors.a1,
                        roster,
                        now: exact.request.expiresAt - 1,
                    }).roster.revision,
                ).toBe(2);
                expect(() =>
                    authorizeDeviceProvisioning({
                        request: exact.request,
                        account: actors.alice,
                        authorDevice: actors.a1,
                        roster,
                        now: exact.request.expiresAt,
                    }),
                ).toThrow("Invalid or expired");
            } finally {
                zeroBytes(below.ephemeralSecretKey);
                zeroBytes(exact.ephemeralSecretKey);
            }

            for (const ttl of [0, -1, PROVISIONING_TTL + 1, Number.MAX_SAFE_INTEGER]) {
                expect(() =>
                    createDeviceLinkMaterial(actors.a2, new Uint8Array([1]), NOW, ttl),
                ).toThrow("Invalid device-link request inputs");
            }
            expect(() => createDeviceLinkMaterial(actors.a2, new Uint8Array(), NOW)).toThrow(
                "Invalid device-link request inputs",
            );
            expect(() =>
                createDeviceLinkMaterial(
                    actors.a2,
                    new Uint8Array(MAXIMUM_KEY_PACKAGE_BYTES + 1),
                    NOW,
                ),
            ).toThrow("Invalid device-link request inputs");
            expect(() => createDeviceLinkMaterial(actors.a2, new Uint8Array([1]), -1)).toThrow(
                "Invalid device-link request inputs",
            );
        } finally {
            zeroBytes(maximum);
            destroyActors(actors);
        }
    });

    test("DEV-02 transcript binding rejects replay mutations and cross-device envelopes", async () => {
        const actors = accountActors();
        const roster = initialRoster(actors.alice, actors.a1);
        const a2Material = createDeviceLinkMaterial(actors.a2, new Uint8Array([1, 2]), NOW);
        const a3Material = createDeviceLinkMaterial(actors.a3, new Uint8Array([3, 4]), NOW);
        const b2Material = createDeviceLinkMaterial(actors.b2, new Uint8Array([5, 6]), NOW);
        try {
            const authorized = authorizeDeviceProvisioning({
                request: a2Material.request,
                account: actors.alice,
                authorDevice: actors.a1,
                roster,
                now: NOW + 1,
            });
            const provisioned = completeDeviceProvisioning(
                a2Material,
                authorized.envelope,
                NOW + 2,
            );
            try {
                expect(provisioned.account.publicKey).toEqual(actors.alice.publicKey);
                expect(isActiveDevice(provisioned.roster, actors.a2.publicKey)).toBe(true);
            } finally {
                destroyIdentity(provisioned.account);
            }
            expect(() =>
                completeDeviceProvisioning(a3Material, authorized.envelope, NOW + 2),
            ).toThrow(/provisioning envelope/);
            expect(() =>
                completeDeviceProvisioning(b2Material, authorized.envelope, NOW + 2),
            ).toThrow(/provisioning envelope/);

            const mutated: MurmurDeviceProvisioningEnvelope = {
                ...authorized.envelope,
                signature: authorized.envelope.signature.slice(),
            };
            mutated.signature[0] = mutated.signature[0]! ^ 1;
            expect(() => completeDeviceProvisioning(a2Material, mutated, NOW + 2)).toThrow(
                "Invalid provisioning envelope",
            );

            const store = new MemoryMurmurStore();
            await observe(store, actors.alice.publicKey, "initial", roster);
            await observe(store, actors.alice.publicKey, "child", authorized.roster, {
                device: actors.a2.publicKey,
                keyPackage: a2Material.request.keyPackage,
            });
            await observe(store, actors.alice.publicKey, "child-replay", authorized.roster, {
                device: actors.a2.publicKey,
                keyPackage: a2Material.request.keyPackage,
            });
            expect(await accountConvergenceJobs(store)).toHaveLength(1);
            expect(
                (await storedRoster(store)).devices.filter((entry) => entry.status === "active"),
            ).toHaveLength(2);
        } finally {
            zeroBytes(a2Material.ephemeralSecretKey);
            zeroBytes(a3Material.ephemeralSecretKey);
            zeroBytes(b2Material.ephemeralSecretKey);
            destroyActors(actors);
        }
    });

    test(
        "DEV-03 real-client crashes roll back link and account-import handoffs",
        { timeout: 60_000 },
        async () => {
            const network = realNetwork();
            const a1 = await openNode("A1", network);
            const a2Delegate = new MemoryMurmurStore();
            const requestCrash = new SeededChaosSchedule(0x44455603, [
                {
                    id: "crash-link-persistence",
                    selector: {
                        operation: "transaction.set",
                        phase: "after",
                        key: "murmur/accounts/v1/link-material",
                    },
                    effect: { type: "crash", message: "crash after link persistence" },
                },
            ]);
            let a2 = await openNode("A2-crash-request", network, {
                store: new FaultInjectingMurmurStore({
                    actor: "A2",
                    delegate: a2Delegate,
                    schedule: requestCrash,
                }),
            });
            try {
                await expect(a2.client.linkDevice()).rejects.toBeInstanceOf(ChaosCrashError);
                expect(await a2Delegate.get("murmur/accounts/v1/link-material")).toBeUndefined();
                a2.close();

                a2 = await openNode("A2-request-retry", network, { store: a2Delegate });
                const request = await a2.client.linkDevice();
                const envelope = await a1.client.authorizeDevice(request);
                a2.close();

                const importCrash = new SeededChaosSchedule(0x44455604, [
                    {
                        id: "crash-account-import",
                        selector: {
                            operation: "transaction.set",
                            phase: "after",
                            key: "murmur/accounts/v1/root",
                        },
                        effect: { type: "crash", message: "crash during account import" },
                    },
                ]);
                a2 = await openNode("A2-crash-import", network, {
                    store: new FaultInjectingMurmurStore({
                        actor: "A2",
                        delegate: a2Delegate,
                        schedule: importCrash,
                    }),
                });
                await expect(a2.client.completeDeviceLink(envelope)).rejects.toBeInstanceOf(
                    ChaosCrashError,
                );
                expect(await a2Delegate.get("murmur/accounts/v1/root")).toBeUndefined();
                a2.close();

                a2 = await openNode("A2-import-retry", network, { store: a2Delegate });
                await a2.client.completeDeviceLink(envelope);
                expect(a2.client.accountKey).toEqual(a1.client.accountKey);
                await expect(a2.client.completeDeviceLink(envelope)).rejects.toThrow(
                    "No pending device link",
                );
                requestCrash.assertConsumed();
                importCrash.assertConsumed();
            } finally {
                a1.close();
                a2.close();
                await network.relay.close();
            }
        },
    );

    test("DEV-04 concurrent roster children select one hash winner independent of order", async () => {
        const actors = accountActors();
        const parent = initialRoster(actors.alice, actors.a1);
        try {
            const left = addDeviceToRoster(
                parent,
                actors.alice,
                actors.a1,
                actors.a2.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(1),
            );
            const right = addDeviceToRoster(
                parent,
                actors.alice,
                actors.a1,
                actors.a3.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(2),
            );
            const winner = selectDeviceRosterChild(parent, [left, right]);
            expect(winner).toBeDefined();
            expect(deviceRosterHash(selectDeviceRosterChild(parent, [right, left])!)).toEqual(
                deviceRosterHash(winner!),
            );

            const firstStore = new MemoryMurmurStore();
            const secondStore = new MemoryMurmurStore();
            for (const store of [firstStore, secondStore]) {
                await observe(store, actors.alice.publicKey, "parent", parent);
            }
            for (const child of [left, right]) {
                await observe(firstStore, actors.alice.publicKey, "fork", child).catch(
                    () => undefined,
                );
            }
            for (const child of [right, left]) {
                await observe(secondStore, actors.alice.publicKey, "fork", child).catch(
                    () => undefined,
                );
            }
            expect(deviceRosterHash(await storedRoster(firstStore))).toEqual(
                deviceRosterHash(await storedRoster(secondStore)),
            );
            expect(deviceRosterHash(await storedRoster(firstStore))).toEqual(
                deviceRosterHash(winner!),
            );

            const missing = isActiveDevice(winner!, actors.a2.publicKey) ? actors.a3 : actors.a2;
            const sequential = addDeviceToRoster(
                winner!,
                actors.alice,
                actors.a1,
                missing.publicKey,
                NOW + 2,
                new Uint8Array(16).fill(3),
            );
            expect(sequential.devices.filter((entry) => entry.status === "active")).toHaveLength(3);
        } finally {
            destroyActors(actors);
        }
    });

    test("DEV-05 a revoked inviter cannot authorize a later roster child", () => {
        const actors = accountActors();
        const initial = initialRoster(actors.alice, actors.a1);
        try {
            const a2Before = addDeviceToRoster(
                initial,
                actors.alice,
                actors.a1,
                actors.a2.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(1),
            );
            const a3AfterA2 = addDeviceToRoster(
                a2Before,
                actors.alice,
                actors.a1,
                actors.a3.publicKey,
                NOW + 2,
                new Uint8Array(16).fill(2),
            );
            const revokedAfterAuthorization = revokeDeviceFromRoster(
                a3AfterA2,
                actors.alice,
                actors.a3,
                actors.a1.publicKey,
                NOW + 3,
                new Uint8Array(16).fill(3),
            );
            expect(isActiveDevice(revokedAfterAuthorization, actors.a2.publicKey)).toBe(true);

            const a3First = addDeviceToRoster(
                initial,
                actors.alice,
                actors.a1,
                actors.a3.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(4),
            );
            const a1Revoked = revokeDeviceFromRoster(
                a3First,
                actors.alice,
                actors.a3,
                actors.a1.publicKey,
                NOW + 2,
                new Uint8Array(16).fill(5),
            );
            expect(() =>
                addDeviceToRoster(
                    a1Revoked,
                    actors.alice,
                    actors.a1,
                    actors.a2.publicKey,
                    NOW + 3,
                    new Uint8Array(16).fill(6),
                ),
            ).toThrow("Roster author is not active");
        } finally {
            destroyActors(actors);
        }
    });

    test("DEV-08 roster rules prevent an active device from deleting the final authority", () => {
        const actors = accountActors();
        const initial = initialRoster(actors.bob, actors.b1);
        try {
            expect(() =>
                revokeDeviceFromRoster(
                    initial,
                    actors.bob,
                    actors.b1,
                    actors.b1.publicKey,
                    NOW + 1,
                    new Uint8Array(16).fill(1),
                ),
            ).toThrow("cannot revoke itself");
            const withB2 = addDeviceToRoster(
                initial,
                actors.bob,
                actors.b1,
                actors.b2.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(2),
            );
            const b2Removed = revokeDeviceFromRoster(
                withB2,
                actors.bob,
                actors.b1,
                actors.b2.publicKey,
                NOW + 2,
                new Uint8Array(16).fill(3),
            );
            expect(b2Removed.devices.filter((entry) => entry.status === "active")).toHaveLength(1);
            expect(() =>
                addDeviceToRoster(
                    b2Removed,
                    actors.bob,
                    actors.b1,
                    actors.b2.publicKey,
                    NOW + 3,
                    new Uint8Array(16).fill(4),
                ),
            ).toThrow("Device already exists");
        } finally {
            destroyActors(actors);
        }
    });

    test("DEV-12 convergence jobs deduplicate, fail closed on corruption, and drain once", async () => {
        const actors = accountActors();
        const initial = initialRoster(actors.alice, actors.a1);
        const added = addDeviceToRoster(
            initial,
            actors.alice,
            actors.a1,
            actors.a2.publicKey,
            NOW + 1,
            new Uint8Array(16).fill(1),
        );
        const delegate = new MemoryMurmurStore();
        try {
            await observe(delegate, actors.alice.publicKey, "initial", initial);
            await observe(delegate, actors.alice.publicKey, "add-a2", added, {
                device: actors.a2.publicKey,
                keyPackage: new Uint8Array([1, 2, 3]),
            });
            await observe(delegate, actors.alice.publicKey, "add-a2-replay", added, {
                device: actors.a2.publicKey,
                keyPackage: new Uint8Array([1, 2, 3]),
            });
            expect(await accountConvergenceJobs(delegate)).toHaveLength(1);

            const schedule = new SeededChaosSchedule(0x44455612, [
                {
                    id: "corrupt-job-scan",
                    selector: {
                        operation: "scan",
                        phase: "after",
                        key: ACCOUNT_CONVERGENCE_PREFIX,
                    },
                    effect: { type: "corrupt", offset: 0, xor: 0xff },
                },
            ]);
            const corrupting = new FaultInjectingMurmurStore({
                actor: "A1",
                delegate,
                schedule,
            });
            await expect(accountConvergenceJobs(corrupting)).rejects.toThrow();
            expect(await accountConvergenceJobs(delegate)).toHaveLength(1);
            const job = (await accountConvergenceJobs(delegate))[0]!;
            await delegate.delete(job.key);
            expect(await accountConvergenceJobs(delegate)).toEqual([]);
            schedule.assertConsumed();
        } finally {
            destroyActors(actors);
        }
    });

    test(
        "DEV-06/07/09/10/11/13 real relay converges six physical devices and revocation",
        { timeout: 180_000 },
        async () => {
            const network = realNetwork();
            const a1 = await openNode("A1", network);
            const a2 = await openNode("A2", network);
            const a3 = await openNode("A3", network);
            const b1 = await openNode("B1", network);
            const b2 = await openNode("B2", network);
            const c1 = await openNode("C1", network);
            const all = [a1, a2, a3, b1, b2, c1];
            try {
                const chat = await a1.client.createSession({
                    descriptor: CHAT_DESCRIPTOR,
                    members: [await b1.client.discovery()],
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: true,
                });
                await settleNodes([a1, b1], 12);

                const a2Request = await a2.client.linkDevice();
                const carolDiscovery = await c1.client.discovery();
                const [a2Envelope] = await Promise.all([
                    a1.client.authorizeDevice(a2Request),
                    b1.client.addMember(chat.id, carolDiscovery),
                ]);
                await a2.client.completeDeviceLink(a2Envelope);
                await pumpAll([a1, a2, b1, c1], 12);

                const a3Request = await a3.client.linkDevice();
                const a3Envelope = await a1.client.authorizeDevice(a3Request);
                await a3.client.completeDeviceLink(a3Envelope);
                const b2Request = await b2.client.linkDevice();
                const b2Envelope = await b1.client.authorizeDevice(b2Request);
                await b2.client.completeDeviceLink(b2Envelope);
                await pumpAll(all, 16);

                const aliceAccount = encodeBase64Url(a1.client.accountKey);
                const bobAccount = encodeBase64Url(b1.client.accountKey);
                const carolAccount = encodeBase64Url(c1.client.accountKey);
                const logicalMembers = [aliceAccount, bobAccount, carolAccount].sort();
                for (const node of all) {
                    const session = await node.client.session(chat.id);
                    expect(session, `${node.name} is missing the converged chat`).toBeDefined();
                    expect(sessionMembers(session)).toEqual(logicalMembers);
                }
                for (const node of [a1, a2, a3]) {
                    const devices = await node.client.devices();
                    expect(devices.filter((device) => device.status === "active")).toHaveLength(3);
                    expect(node.client.accountKey).toEqual(a1.client.accountKey);
                }
                for (const node of [b1, b2]) {
                    expect(
                        (await node.client.devices()).filter(
                            (device) => device.status === "active",
                        ),
                    ).toHaveLength(2);
                    expect(node.client.accountKey).toEqual(b1.client.accountKey);
                }

                const offlineLabels = Array.from({ length: 5 }, (_, index) => `offline-${index}`);
                for (const label of offlineLabels) {
                    await b1.client.send(chat.id, utf8Encode(label));
                    await pumpAll([a1, a3, b1, b2, c1], 2);
                }
                expect(a2.messages).not.toEqual(expect.arrayContaining(offlineLabels));
                await settleNodes(all, 16);
                expect(a2.messages.filter((label) => label.startsWith("offline-"))).toEqual(
                    offlineLabels,
                );

                await Promise.all([
                    a1.client.setPolicies(chat.id, {
                        adminsAssignAdmins: true,
                        anyoneCanAddMembers: false,
                    }),
                    a2.client.setPolicies(chat.id, {
                        adminsAssignAdmins: false,
                        anyoneCanAddMembers: true,
                    }),
                ]);
                const stagedA1 = await a1.client.send(chat.id, utf8Encode("staged-a1"));
                const stagedA2 = await a2.client.send(chat.id, utf8Encode("staged-a2"));
                await settleNodes(all, 24);
                for (const node of all) {
                    expect(node.messages).toEqual(
                        expect.arrayContaining(["staged-a1", "staged-a2"]),
                    );
                    expect(sessionMembers(await node.client.session(chat.id))).toEqual(
                        logicalMembers,
                    );
                }
                expect(publishedById(a1, stagedA1).id).toBe(stagedA1);
                expect(publishedById(a2, stagedA2).id).toBe(stagedA2);

                const activePhysical = sortedKeys(all.map((node) => node.client.identity));
                const fanoutLabels = new Map<DeviceNode, string>();
                for (const node of all) {
                    const label = `fanout-${node.name}`;
                    fanoutLabels.set(node, label);
                    const id = await node.client.send(chat.id, utf8Encode(label));
                    await node.pump();
                    expect(sortedKeys(publishedById(node, id).recipients)).toEqual(activePhysical);
                }
                await settleNodes(all, 20);
                for (const receiver of all) {
                    expect(receiver.messages).toEqual(
                        expect.arrayContaining([...fanoutLabels.values()]),
                    );
                }

                await a2.client.revokeDevice(a1.client.identity);
                await settleNodes([a2, a3, b1, b2, c1], 24);
                const aliceDevices = await a2.client.devices();
                expect(aliceDevices.filter((device) => device.status === "active")).toHaveLength(2);
                expect(
                    aliceDevices.find((device) => equalBytes(device.deviceKey, a1.client.identity))
                        ?.status,
                ).toBe("revoked");
                const ownerView = await a2.client.session(chat.id);
                expect(encodeBase64Url(ownerView!.owner)).toBe(aliceAccount);
                expect(ownerView!.admins.map(encodeBase64Url)).toContain(aliceAccount);

                const revokedMessageCount = a1.messages.length;
                const afterRevocationId = await b1.client.send(
                    chat.id,
                    utf8Encode("after-a1-revocation"),
                );
                await b1.pump();
                expect(sortedKeys(publishedById(b1, afterRevocationId).recipients)).toEqual(
                    sortedKeys([a2, a3, b1, b2, c1].map((node) => node.client.identity)),
                );
                await settleNodes([a2, a3, b1, b2, c1], 12);
                await a1.pump().catch(() => undefined);
                expect(a1.messages.slice(revokedMessageCount)).not.toContain("after-a1-revocation");
                await expect(
                    a1.client.send(chat.id, utf8Encode("revoked-authority-send")),
                ).rejects.toThrow();

                await a2.client.setPolicies(chat.id, {
                    adminsAssignAdmins: true,
                    anyoneCanAddMembers: true,
                });
                await a2.client.send(chat.id, utf8Encode("owner-continuity"));
                await settleNodes([a2, a3, b1, b2, c1], 16);
                for (const node of [a2, a3, b1, b2, c1]) {
                    expect(node.messages).toContain("owner-continuity");
                    expect(sessionMembers(await node.client.session(chat.id))).toEqual(
                        logicalMembers,
                    );
                }
            } finally {
                for (const node of all) node.close();
                await network.relay.close();
            }
        },
    );

    test(
        "DEV-14 32 fixed seeds replay fifty authenticated roster actions",
        { timeout: 120_000 },
        async () => {
            interface CampaignResult {
                readonly revision: number;
                readonly statuses: readonly string[];
                readonly sends: number;
                readonly intents: number;
                readonly transitions: number;
            }

            const deterministicIdentity = (seed: number, index: number): IdentityKeyPair => {
                const secret = new Uint8Array(32);
                const view = new DataView(secret.buffer);
                for (let offset = 0; offset < secret.length; offset += 4) {
                    view.setUint32(offset, (seed + index * 0x9e3779b9 + offset) >>> 0);
                }
                try {
                    return importIdentityKeyPair(secret);
                } finally {
                    zeroBytes(secret);
                }
            };

            const run = async (seed: number): Promise<CampaignResult> => {
                const random = new SeededRandom(seed);
                const clock = new ManualVirtualClock(NOW);
                const account = deterministicIdentity(seed, 0);
                const devices = Array.from({ length: 6 }, (_, index) =>
                    deterministicIdentity(seed, index + 1),
                );
                let roster = createInitialDeviceRoster(
                    account,
                    devices[0]!,
                    clock.now(),
                    new Uint8Array(16),
                );
                let sends = 0;
                let intents = 0;
                try {
                    for (let transition = 0; transition < 50; transition += 1) {
                        clock.advance(1);
                        const action = random.integer(0, 5);
                        const active = devices.filter((device) =>
                            isActiveDevice(roster, device.publicKey),
                        );
                        const absent = devices.filter(
                            (device) =>
                                !roster.devices.some((entry) =>
                                    equalBytes(entry.deviceKey, device.publicKey),
                                ),
                        );
                        const author = active[random.integer(0, active.length)]!;
                        const mutation = new Uint8Array(16).fill(transition + 1);
                        if ((action === 0 || action === 1) && absent.length > 0) {
                            const candidate = absent[random.integer(0, absent.length)]!;
                            if (action === 0) {
                                roster = addDeviceToRoster(
                                    roster,
                                    account,
                                    author,
                                    candidate.publicKey,
                                    clock.now(),
                                    mutation,
                                );
                            } else {
                                const material = createDeviceLinkMaterial(
                                    candidate,
                                    new Uint8Array([transition + 1]),
                                    clock.now(),
                                );
                                try {
                                    const authorized = authorizeDeviceProvisioning({
                                        request: material.request,
                                        account,
                                        authorDevice: author,
                                        roster,
                                        now: clock.now(),
                                    });
                                    const provisioned = completeDeviceProvisioning(
                                        material,
                                        authorized.envelope,
                                        clock.now(),
                                    );
                                    destroyIdentity(provisioned.account);
                                    roster = addDeviceToRoster(
                                        roster,
                                        account,
                                        author,
                                        candidate.publicKey,
                                        clock.now(),
                                        mutation,
                                    );
                                } finally {
                                    zeroBytes(material.ephemeralSecretKey);
                                }
                            }
                        } else if (action === 2 && active.length > 1) {
                            const removable = active.filter(
                                (device) => !equalBytes(device.publicKey, author.publicKey),
                            );
                            const target = removable[random.integer(0, removable.length)]!;
                            roster = revokeDeviceFromRoster(
                                roster,
                                account,
                                author,
                                target.publicKey,
                                clock.now(),
                                mutation,
                            );
                        } else if (action === 3) {
                            roster = parseDeviceRoster(serializeDeviceRoster(roster));
                        } else if (action === 4 && absent.length >= 2) {
                            const left = addDeviceToRoster(
                                roster,
                                account,
                                author,
                                absent[0]!.publicKey,
                                clock.now(),
                                mutation,
                            );
                            const right = addDeviceToRoster(
                                roster,
                                account,
                                author,
                                absent[1]!.publicKey,
                                clock.now(),
                                new Uint8Array(16).fill(transition + 2),
                            );
                            roster = selectDeviceRosterChild(roster, [right, left])!;
                        }
                        if (transition < 30) sends += 1;
                        if (transition < 10) intents += 1;
                    }
                    const settled = await settleChaos({
                        maximumRounds: 4,
                        act: () => undefined,
                        snapshot: () => serializeDeviceRoster(roster),
                        equal: equalBytes,
                    });
                    expect(settled.rounds).toBe(2);
                    return {
                        revision: roster.revision,
                        statuses: devices.map((device) => {
                            const entry = roster.devices.find((candidate) =>
                                equalBytes(candidate.deviceKey, device.publicKey),
                            );
                            return entry?.status ?? "absent";
                        }),
                        sends,
                        intents,
                        transitions: 50,
                    };
                } finally {
                    destroyIdentity(account);
                    for (const device of devices) destroyIdentity(device);
                }
            };

            for (let seed = 0x44455600; seed <= 0x4445561f; seed += 1) {
                try {
                    const first = await run(seed);
                    const replay = await run(seed);
                    expect(first).toEqual(replay);
                    expect(first).toMatchObject({ sends: 30, intents: 10, transitions: 50 });
                    await new Promise<void>((resolve) => setTimeout(resolve, 0));
                } catch (error: unknown) {
                    throw new Error(`DEV-14 seed=0x${seed.toString(16).padStart(8, "0")}`, {
                        cause: error,
                    });
                }
            }
        },
    );
});
