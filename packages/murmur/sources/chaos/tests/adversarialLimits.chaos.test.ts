import {
    DELIVERY_RETENTION_MILLISECONDS,
    PrivateGroupStateService,
    RelayService,
    SqlitePrivateGroupStateStore,
    SqliteRelayStore,
    createRelayFetchHandler,
    type RelayOptions,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    addDeviceToRoster,
    authorizeDeviceProvisioning,
    completeDeviceProvisioning,
    createDeviceLinkMaterial,
    createInitialDeviceRoster,
    decodeAccountSyncPacket,
    encodeAccountSyncPacket,
    isActiveDevice,
    parseDeviceLinkRequest,
    parseDeviceRoster,
    parseProvisioningEnvelope,
    resetDeviceInRoster,
    revokeDeviceFromRoster,
    selectDeviceRosterChild,
    serializeDeviceLinkRequest,
    serializeDeviceRoster,
    serializeProvisioningEnvelope,
} from "../../accounts/index.js";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    hashBytes,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import {
    HttpDeliveryTransport,
    InboxContinuityLossError,
    InboxProcessor,
    TerminalInboxDeliveryError,
    WebSocketDeliveryTransport,
    containsRecipient,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    parseSignedDelivery,
    signedDeliveryToJson,
    type DeliveryFetch,
    type DeliveryWebSocket,
    type DeliveryWebSocketCloseEvent,
    type DeliveryWebSocketMessageEvent,
    type RelaySessionProvider,
    type SignedDelivery,
} from "../../delivery/index.js";
import {
    createDiscoveryBundle,
    parseDiscoveryBundle,
    serializeDiscoveryBundle,
    verifyDiscoveryBundle,
} from "../../identity/discovery/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    type MlsKeyPackageBundle,
} from "../../mls/index.js";
import { type MlsGroupContext } from "../../mls/groupContext/index.js";
import {
    decodeMlsPrivateMessage,
    encodeMlsPrivateMessage,
    openMlsApplicationMessage,
    sealMlsApplicationMessage,
} from "../../mls/privateMessage/index.js";
import { MlsSecretTree, destroyMlsGenerationKey } from "../../mls/secretTree/index.js";
import {
    PrivateGroupStateClient,
    createPrivateGroupCredentialAuthority,
    type PrivateGroupRecordContent,
} from "../../privateGroupState/index.js";
import {
    createCredentialIssuanceRequest,
    createEncryptedUid,
    createUidPresentation,
    decodeCredentialIssuanceResponse,
    decodeUidPresentation,
    deriveCredentialIssuer,
    derivePrivateGroupParameters,
    encodeCredentialIssuanceResponse,
    encodeUidPresentation,
    finalizeCredentialIssuance,
    issueCredential,
    privateGroupPublicParameters,
    verifyUidPresentation,
} from "../../privateGroups/index.js";
import { MurmurClient, type MurmurUpdate } from "../../sessions/index.js";
import {
    decodeSessionRoles,
    encodeAccountResetCiphertext,
    encodeSessionRoles,
    openCommitCiphertext,
    parseSessionCiphertext,
    sealCommitCiphertext,
    type SessionRoles,
} from "../../sessions/impl/sessionFrames.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    canonicalJsonBytes,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import { SeededRandom } from "../index.js";

const NOW = 1_700_000_000_000;
const MINUTE_MILLISECONDS = 60_000;
const SIX_MONTHS_MILLISECONDS = 180 * 24 * 60 * MINUTE_MILLISECONDS;
const STREAM_EVENT_ID = "018bcfe5-6800-7000-8000-000000000001";
const STREAM_GENERATION = encodeBase64Url(new Uint8Array(32));

interface WebSocketRequestFrame {
    readonly version: 1;
    readonly id: string;
    readonly operation: "publish" | "read" | "acknowledge" | "stream";
    readonly body: unknown;
}

class ScriptedWebSocket implements DeliveryWebSocket {
    readyState = 0;
    onopen: (() => void) | null = null;
    onmessage: ((event: DeliveryWebSocketMessageEvent) => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: ((event: DeliveryWebSocketCloseEvent) => void) | null = null;
    readonly #handle: (frame: WebSocketRequestFrame, socket: ScriptedWebSocket) => void;

    constructor(handle: (frame: WebSocketRequestFrame, socket: ScriptedWebSocket) => void) {
        this.#handle = handle;
        queueMicrotask(() => {
            this.readyState = 1;
            this.onopen?.();
        });
    }

    send(data: string): void {
        this.#handle(JSON.parse(data) as WebSocketRequestFrame, this);
    }

    close(): void {
        this.readyState = 3;
    }

    receive(data: unknown): void {
        this.onmessage?.({ data });
    }
}

function relaySessionProvider(): RelaySessionProvider {
    return {
        issue: async () => ({
            version: 1,
            protocol: "murmur-websocket-v1",
            endpoint: "wss://relay.test/v2/connect",
            token: "adversarial.ticket",
            expiresAt: NOW + MINUTE_MILLISECONDS,
        }),
    };
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "adversarial-limits-chaos",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

interface RelayFixture {
    readonly relay: RelayService;
    readonly transport: HttpDeliveryTransport;
}

function relayFixture(options: RelayOptions = {}, now: () => number = () => NOW): RelayFixture {
    const relay = new RelayService(new SqliteRelayStore(":memory:"), options, undefined, now);
    return {
        relay,
        transport: new HttpDeliveryTransport("https://relay.test", { fetch: relayFetch(relay) }),
    };
}

function delivery(
    sender: IdentityKeyPair,
    recipients: readonly Uint8Array[],
    bytes: Uint8Array,
    createdAt: number = NOW,
    expiresAt: number = NOW + MINUTE_MILLISECONDS,
): SignedDelivery {
    return createSignedDelivery(sender, recipients, bytes, { createdAt, expiresAt });
}

function flip(bytes: Uint8Array, index: number = bytes.length - 1): Uint8Array {
    const result = bytes.slice();
    if (result.length > 0) {
        const offset = Math.max(0, Math.min(index, result.length - 1));
        result[offset] = (result[offset] ?? 0) ^ 1;
    }
    return result;
}

function context(epoch: bigint = 7n): MlsGroupContext {
    return {
        groupId: utf8Encode("adversarial-group"),
        epoch,
        treeHash: hashBytes(utf8Encode("tree")),
        confirmedTranscriptHash: hashBytes(utf8Encode("transcript")),
    };
}

function objectJson(bytes: Uint8Array): Record<string, unknown> {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Expected JSON object");
    }
    return parsed as Record<string, unknown>;
}

async function closeFixture(
    fixture: RelayFixture,
    identities: readonly IdentityKeyPair[],
): Promise<void> {
    await fixture.relay.close();
    for (const identity of identities) destroyIdentity(identity);
}

describe("adversarial inputs and resource limits", () => {
    test("ADV-01/15 poison classes cannot starve later valid work and diagnostics stay bounded", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const effects: string[] = [];
        const poisonClasses = [
            "application",
            "commit",
            "welcome",
            "discovery",
            "provisioning",
            "role-control",
            "account-roster",
            "private-group",
        ] as const;
        const processor = new InboxProcessor(
            { identity: recipient, transport: fixture.transport, store },
            async (transaction, queued) => {
                const label = utf8Decode(queued.delivery.ciphertext);
                if (label.startsWith("poison/")) {
                    throw new TerminalInboxDeliveryError(
                        `invalid_${label.slice("poison/".length).replaceAll("-", "_")}`,
                    );
                }
                await transaction.set(`application/${queued.delivery.id}`, utf8Encode(label));
                effects.push(label);
            },
            { now: () => NOW, maximumRejections: 8 },
        );
        try {
            for (let index = 0; index < 100; index += 1) {
                const label = poisonClasses[index % poisonClasses.length]!;
                await fixture.transport.publish(
                    delivery(sender, [recipient.publicKey], utf8Encode(`poison/${label}`)),
                );
            }
            await fixture.transport.publish(
                delivery(sender, [recipient.publicKey], utf8Encode("valid-after-poison")),
            );

            await expect(processor.synchronize({ limit: 50 })).resolves.toMatchObject({
                processed: 0,
                rejected: 50,
                exhausted: false,
            });
            await expect(processor.synchronize({ limit: 50 })).resolves.toMatchObject({
                processed: 0,
                rejected: 50,
                exhausted: false,
            });
            await expect(processor.synchronize({ limit: 50 })).resolves.toMatchObject({
                processed: 1,
                rejected: 0,
                exhausted: true,
            });

            expect(effects).toEqual(["valid-after-poison"]);
            expect(await store.list("application/")).toHaveLength(1);
            expect(await processor.rejections()).toHaveLength(8);
            expect(await processor.continuity()).toMatchObject({ sequence: 101 });
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-02/05 tampered MLS messages and 64-bit jumps do not burn current traffic", () => {
        const signer = generateIdentityKeyPair();
        const encryptionSecret = hashBytes(utf8Encode("encryption"));
        const senderDataSecret = hashBytes(utf8Encode("sender-data"));
        const senderTree = new MlsSecretTree(encryptionSecret, 1);
        const receiverTree = new MlsSecretTree(encryptionSecret, 1);
        try {
            const valid = sealMlsApplicationMessage({
                context: context(),
                sender: 0,
                signingSecretKey: signer.secretKey,
                senderDataSecret,
                secretTree: senderTree,
                applicationData: utf8Encode("valid-current"),
            });
            const parsed = decodeMlsPrivateMessage(valid);
            const tampered = encodeMlsPrivateMessage({
                ...parsed,
                ciphertext: flip(parsed.ciphertext),
            });
            expect(() =>
                openMlsApplicationMessage({
                    context: context(),
                    senderDataSecret,
                    secretTree: receiverTree,
                    message: tampered,
                    signatureKeyFor: () => signer.publicKey,
                }),
            ).toThrow();
            expect(
                utf8Decode(
                    openMlsApplicationMessage({
                        context: context(),
                        senderDataSecret,
                        secretTree: receiverTree,
                        message: valid,
                        signatureKeyFor: () => signer.publicKey,
                    }).applicationData,
                ),
            ).toBe("valid-current");

            for (const epoch of [0n, 6n, 8n, 9n, 7n + 2n ** 16n, 7n + 2n ** 32n, 2n ** 64n - 1n]) {
                const tree = new MlsSecretTree(encryptionSecret, 1);
                try {
                    expect(() =>
                        openMlsApplicationMessage({
                            context: context(),
                            senderDataSecret,
                            secretTree: tree,
                            message: encodeMlsPrivateMessage({ ...parsed, epoch }),
                            signatureKeyFor: () => signer.publicKey,
                        }),
                    ).toThrow();
                } finally {
                    tree.destroy();
                }
            }

            const bounded = new MlsSecretTree(encryptionSecret, 1, 2, 4);
            const generationTwo = bounded.take(0, "application", 2);
            destroyMlsGenerationKey(generationTwo);
            const skippedZero = bounded.take(0, "application", 0);
            destroyMlsGenerationKey(skippedZero);
            expect(() => bounded.take(0, "application", 2 ** 16)).toThrow("too far");
            expect(() => bounded.take(0, "application", 2 ** 32 - 1)).toThrow("too far");
            expect(() => bounded.take(0, "application", 2 ** 32)).toThrow("Invalid");
            bounded.destroy();
        } finally {
            senderTree.destroy();
            receiverTree.destroy();
            zeroBytes(encryptionSecret);
            zeroBytes(senderDataSecret);
            destroyIdentity(signer);
        }
    });

    test("ADV-03/04 an earlier malformed Commit cannot block the first valid role Commit", async () => {
        const fixture = relayFixture();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const attacker = generateIdentityKeyPair();
        const alice = await MurmurClient.open({
            identity: aliceIdentity,
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open({
            identity: bobIdentity,
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("adversarial-commit-order"),
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.activateSession(session.id);

            const poison = delivery(
                attacker,
                [bobIdentity.publicKey],
                new Uint8Array([3, 0xff, 0x00]),
            );
            await fixture.transport.publish(poison);
            await alice.setPolicies(session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            const synchronized = await bob.synchronize({ waitMilliseconds: 0 });

            expect(synchronized.inbox).toMatchObject({ rejected: 1, processed: 1 });
            expect(await bob.session(session.id)).toMatchObject({
                policies: { adminsAssignAdmins: true, anyoneCanAddMembers: true },
            });

            await alice.send(session.id, utf8Encode("live-after-invalid-commit"));
            await alice.synchronize({ waitMilliseconds: 0 });
            const updates: MurmurUpdate[] = [];
            await bob.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (batch) => {
                        updates.push(...batch);
                    },
                },
            );
            expect(updates.map((update) => utf8Decode(update.bytes))).toContain(
                "live-after-invalid-commit",
            );
        } finally {
            alice.close();
            bob.close();
            await closeFixture(fixture, [aliceIdentity, bobIdentity, attacker]);
        }
    }, 120_000);

    test("ADV-04 role and Commit framing rejects swaps and malformed controls", () => {
        const owner = new Uint8Array(32).fill(1);
        const admin = new Uint8Array(32).fill(2);
        const roles: SessionRoles = {
            owner,
            admins: [admin],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
        };
        const key = hashBytes(utf8Encode("commit-key"));
        const groupId = utf8Encode("group-a");
        try {
            const wire = parseSessionCiphertext(
                sealCommitCiphertext(key, {
                    version: 1,
                    groupId,
                    epoch: 7n,
                    commit: utf8Encode("valid-commit"),
                    roles,
                }),
            );
            expect(wire.kind).toBe("commit");
            if (wire.kind !== "commit") throw new Error("Expected Commit ciphertext");
            expect(openCommitCiphertext(key, wire)).toMatchObject({ epoch: 7n, roles });
            expect(() =>
                openCommitCiphertext(key, { ...wire, groupId: utf8Encode("group-b") }),
            ).toThrow();
            expect(() => openCommitCiphertext(key, { ...wire, epoch: 8n })).toThrow();
            expect(() => openCommitCiphertext(flip(key), wire)).toThrow();

            const canonical = objectJson(encodeSessionRoles(roles));
            const malformed = [
                { ...canonical, owner: encodeBase64Url(new Uint8Array(31)) },
                { ...canonical, admins: [encodeBase64Url(admin), encodeBase64Url(admin)] },
                { ...canonical, admins: [encodeBase64Url(owner)] },
                { ...canonical, adminsAssignAdmins: 1 },
                { ...canonical, unknownPolicy: true },
            ];
            for (const value of malformed) {
                expect(() => decodeSessionRoles(utf8Encode(JSON.stringify(value)))).toThrow();
            }
        } finally {
            zeroBytes(key);
            zeroBytes(owner);
            zeroBytes(admin);
        }
    });

    // PRODUCT FINDING: parseSessionCiphertext currently accepts unbounded decimal epochs,
    // including the uint64 wrap at 2^64. Keep the exact uint64 maximum as the live control.
    test.fails("ADV-05 PRODUCT FINDING Commit framing enforces the uint64 epoch ceiling", () => {
        const frame = (epoch: bigint): Uint8Array =>
            new Uint8Array([
                3,
                ...canonicalJsonBytes({
                    version: 1,
                    groupId: encodeBase64Url(utf8Encode("overflow-group")),
                    epoch: epoch.toString(),
                    nonce: encodeBase64Url(new Uint8Array(12)),
                    ciphertext: encodeBase64Url(new Uint8Array(16)),
                }),
            ]);
        expect(parseSessionCiphertext(frame(2n ** 64n - 1n))).toMatchObject({
            kind: "commit",
            epoch: 2n ** 64n - 1n,
        });
        for (const overflow of [2n ** 64n, 2n ** 64n + 1n, 2n ** 128n]) {
            expect(() => parseSessionCiphertext(frame(overflow))).toThrow(
                "Invalid Commit ciphertext",
            );
        }
    });

    test("ADV-06 discovery count, identity, time, encoding, cache, and size boundaries fail closed", async () => {
        let now = NOW;
        const fixture = relayFixture(
            {
                maximumInvitationItemsPerAdmissionPrincipal: 1,
                maximumGlobalInvitationItems: 2,
                maximumInvitationItemsPerRevocationKey: 2,
            },
            () => now,
        );
        const identity = generateIdentityKeyPair();
        const other = generateIdentityKeyPair();
        const packages: MlsKeyPackageBundle[] = [];
        try {
            while (packages.length < 33) {
                packages.push(createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600));
            }
            expect(() => createDiscoveryBundle(identity, [], { createdAt: NOW })).toThrow();
            expect(() =>
                createDiscoveryBundle(
                    identity,
                    packages.map((value) => value.keyPackage),
                    { createdAt: NOW, expiresAt: NOW + MINUTE_MILLISECONDS },
                ),
            ).toThrow();
            expect(
                createDiscoveryBundle(
                    identity,
                    packages.slice(0, 32).map((value) => value.keyPackage),
                    { createdAt: NOW, expiresAt: NOW + MINUTE_MILLISECONDS },
                ).keyPackages,
            ).toHaveLength(32);
            expect(() =>
                createDiscoveryBundle(
                    identity,
                    [packages[0]!.keyPackage, packages[0]!.keyPackage],
                    { createdAt: NOW, expiresAt: NOW + MINUTE_MILLISECONDS },
                ),
            ).toThrow("Duplicate");

            const valid = createDiscoveryBundle(identity, [packages[0]!.keyPackage], {
                createdAt: NOW,
                expiresAt: NOW + MINUTE_MILLISECONDS,
            });
            const encoded = serializeDiscoveryBundle(valid);
            expect(
                verifyDiscoveryBundle(parseDiscoveryBundle(encoded, { now: NOW }), { now: NOW }),
            ).toBe(true);
            const json = objectJson(encoded);
            for (const mutation of [
                { ...json, extra: true },
                { ...json, identityKey: encodeBase64Url(other.publicKey) },
                { ...json, signature: `${String(json.signature)}=` },
                { ...json, keyPackages: [] },
                { ...json, keyPackages: Array.from({ length: 33 }, () => "AA") },
            ]) {
                expect(() =>
                    parseDiscoveryBundle(utf8Encode(JSON.stringify(mutation)), { now: NOW }),
                ).toThrow();
            }
            expect(() =>
                parseDiscoveryBundle(encoded, { now: NOW + MINUTE_MILLISECONDS }),
            ).toThrow();
            expect(() =>
                parseDiscoveryBundle(encoded, {
                    now: NOW - 30_001,
                    maximumFutureSkewMilliseconds: 30_000,
                }),
            ).toThrow();

            const stored = await fixture.relay.storeInvitation(encoded, "principal-a");
            expect((await fixture.relay.storeInvitation(encoded, "principal-a")).duplicate).toBe(
                true,
            );
            await expect(fixture.relay.readInvitation(flip(stored.digest))).rejects.toMatchObject({
                status: 404,
            });
            const second = createDiscoveryBundle(identity, [packages[1]!.keyPackage], {
                createdAt: NOW,
                expiresAt: NOW + MINUTE_MILLISECONDS,
            });
            await expect(
                fixture.relay.storeInvitation(serializeDiscoveryBundle(second), "principal-a"),
            ).rejects.toMatchObject({ status: 429 });
            now = NOW + MINUTE_MILLISECONDS;
            await expect(fixture.relay.readInvitation(stored.digest)).rejects.toMatchObject({
                status: 404,
            });

            const exact = relayFixture({ maximumInvitationBytes: encoded.length });
            const short = relayFixture({ maximumInvitationBytes: encoded.length - 1 });
            try {
                await expect(exact.relay.storeInvitation(encoded, "exact")).resolves.toBeDefined();
                await expect(short.relay.storeInvitation(encoded, "short")).rejects.toMatchObject({
                    status: 413,
                });
            } finally {
                await exact.relay.close();
                await short.relay.close();
            }
        } finally {
            for (const value of packages) destroyMlsKeyPackageBundle(value);
            await closeFixture(fixture, [identity, other]);
        }
    }, 120_000);

    test("ADV-07/08 signed delivery, authentication, fanout, quota, and retention boundaries", async () => {
        expect(DELIVERY_RETENTION_MILLISECONDS).toBe(SIX_MONTHS_MILLISECONDS);
        const fixture = relayFixture({
            maximumCiphertextBytes: 4,
            maximumRecipients: 2,
            maximumDeliveryTtlMilliseconds: SIX_MONTHS_MILLISECONDS,
            maximumAuthenticationSkewMilliseconds: 1,
            maximumSenderReferences: 2,
            maximumAdmissionReferences: 2,
            maximumGlobalReferences: 2,
        });
        const sender = generateIdentityKeyPair();
        const first = generateIdentityKeyPair();
        const second = generateIdentityKeyPair();
        const third = generateIdentityKeyPair();
        try {
            const exact = delivery(
                sender,
                [first.publicKey, second.publicKey],
                new Uint8Array(4),
                NOW,
                NOW + SIX_MONTHS_MILLISECONDS,
            );
            await expect(fixture.transport.publish(exact)).resolves.toMatchObject({
                duplicate: false,
            });
            await expect(fixture.transport.publish(exact)).resolves.toMatchObject({
                duplicate: true,
            });
            await expect(
                fixture.transport.publish(delivery(sender, [first.publicKey], new Uint8Array(5))),
            ).rejects.toMatchObject({ status: 413 });
            await expect(
                fixture.transport.publish(
                    delivery(
                        sender,
                        [first.publicKey, second.publicKey, third.publicKey],
                        new Uint8Array(1),
                    ),
                ),
            ).rejects.toMatchObject({ status: 413 });
            await expect(
                fixture.transport.publish(
                    delivery(
                        sender,
                        [first.publicKey],
                        new Uint8Array(1),
                        NOW,
                        NOW + SIX_MONTHS_MILLISECONDS + 1,
                    ),
                ),
            ).rejects.toMatchObject({ status: 401 });

            const forged = { ...exact, signature: flip(exact.signature) };
            await expect(fixture.relay.publish(forged, "forged")).rejects.toMatchObject({
                status: 401,
            });
            expect(containsRecipient(exact, third.publicKey)).toBe(false);
            expect(() =>
                createSignedDelivery(sender, [], new Uint8Array(1), {
                    createdAt: NOW,
                    expiresAt: NOW + 1,
                }),
            ).toThrow();
            expect(() =>
                createSignedDelivery(
                    sender,
                    [first.publicKey, first.publicKey],
                    new Uint8Array(1),
                    {
                        createdAt: NOW,
                        expiresAt: NOW + 1,
                    },
                ),
            ).toThrow();

            const wrongRead = {
                ...createSignedInboxRead(first, { createdAt: NOW }),
                recipient: second.publicKey,
            };
            await expect(fixture.relay.readQueue(wrongRead)).rejects.toMatchObject({ status: 401 });
            const firstPage = await fixture.transport.read(
                createSignedInboxRead(first, { createdAt: NOW }),
            );
            const eventId = firstPage.deliveries[0]!.eventId;
            const wrongAck = {
                ...createSignedInboxAck(first, eventId, NOW),
                recipient: second.publicKey,
            };
            await expect(fixture.relay.acknowledge(wrongAck)).rejects.toMatchObject({
                status: 401,
            });
            await expect(
                fixture.relay.readQueue(createSignedInboxRead(first, { createdAt: NOW + 2 })),
            ).rejects.toMatchObject({ status: 401 });

            await expect(
                fixture.transport.publish(
                    delivery(sender, [third.publicKey], new Uint8Array(1), NOW, NOW + 2),
                ),
            ).rejects.toMatchObject({ status: 503 });
        } finally {
            await closeFixture(fixture, [sender, first, second, third]);
        }
    });

    test("ADV-07 forged continuity metadata is rejected before durable continuity accounting", async () => {
        const recipient = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const validRead = createSignedInboxRead(recipient, { createdAt: NOW });
        const malformedPages: readonly Record<string, unknown>[] = [
            {
                deliveries: [],
                head: null,
                headSequence: 0,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
                generation: encodeBase64Url(new Uint8Array(31)),
                exhausted: true,
            },
            {
                deliveries: [],
                head: null,
                headSequence: -1,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
                generation: encodeBase64Url(new Uint8Array(32)),
                exhausted: true,
            },
            {
                deliveries: [],
                head: null,
                headSequence: 0,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
                generation: encodeBase64Url(new Uint8Array(32)),
                exhausted: true,
                forged: true,
            },
        ];
        try {
            for (const page of malformedPages) {
                const transport = new HttpDeliveryTransport("https://relay.test", {
                    fetch: async (): Promise<Response> =>
                        new Response(JSON.stringify(page), {
                            status: 200,
                            headers: { "content-type": "application/json" },
                        }),
                });
                const processor = new InboxProcessor(
                    { identity: recipient, transport, store },
                    async () => undefined,
                    { now: () => NOW },
                );
                await expect(processor.synchronize()).rejects.toThrow();
                expect(await processor.continuity()).toBeUndefined();
            }
            expect(validRead.recipient).toEqual(recipient.publicKey);
        } finally {
            destroyIdentity(recipient);
        }
    });

    test("ADV-07 late replay advances sequence once and a restored generation stops processing", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const effects: string[] = [];
        const processor = new InboxProcessor(
            {
                identity: recipient,
                transport: fixture.transport,
                store: new MemoryMurmurStore(),
            },
            async (_transaction, queued) => {
                effects.push(queued.delivery.id);
            },
            { now: () => NOW },
        );
        try {
            const replayed = delivery(sender, [recipient.publicKey], utf8Encode("late replay"));
            const firstPublication = await fixture.transport.publish(replayed);
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 1,
                rejected: 0,
            });
            const firstContinuity = await processor.continuity();
            expect(firstContinuity).toMatchObject({ sequence: 1 });

            const latePublication = await fixture.transport.publish(replayed);
            expect(latePublication).toMatchObject({ duplicate: false });
            expect(latePublication.eventId).not.toBe(firstPublication.eventId);
            await expect(processor.synchronize()).resolves.toMatchObject({
                processed: 0,
                rejected: 1,
            });
            expect(effects).toEqual([replayed.id]);
            const replayContinuity = await processor.continuity();
            expect(replayContinuity).toMatchObject({ sequence: 2 });
            expect(replayContinuity?.generation).toEqual(firstContinuity?.generation);

            await expect(fixture.relay.declareRestored()).resolves.toBe(1);
            const afterRestore = delivery(
                sender,
                [recipient.publicKey],
                utf8Encode("must wait for reset"),
            );
            await fixture.transport.publish(afterRestore);
            const loss = await processor.synchronize().catch((error: unknown) => error);
            expect(loss).toBeInstanceOf(InboxContinuityLossError);
            expect(loss).toMatchObject({
                reason: "generation_changed",
                expectedSequence: 3,
                observedSequence: 3,
            });
            expect(await processor.continuity()).toEqual(replayContinuity);
            expect(effects).toEqual([replayed.id]);

            const pending = await fixture.transport.read(
                createSignedInboxRead(recipient, {
                    after: latePublication.eventId,
                    createdAt: NOW,
                }),
            );
            expect(pending.deliveries).toMatchObject([
                { sequence: 3, delivery: { id: afterRestore.id } },
            ]);
            expect(pending.generation).not.toEqual(replayContinuity?.generation);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-09 concurrent and sequential discovery claims admit one KeyPackage exactly once", async () => {
        const fixture = relayFixture();
        const alice = await MurmurClient.open({
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open({
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const replayed = await bob.discovery();
            const concurrent = await Promise.allSettled([
                alice.createSession({
                    descriptor: utf8Encode("concurrent KeyPackage claim A"),
                    members: [replayed],
                }),
                alice.createSession({
                    descriptor: utf8Encode("concurrent KeyPackage claim B"),
                    members: [replayed],
                }),
            ]);
            expect(concurrent.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
            expect(concurrent.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
            expect(concurrent.find((outcome) => outcome.status === "rejected")).toMatchObject({
                reason: expect.objectContaining({
                    message: expect.stringContaining("already used"),
                }),
            });
            expect((await alice.sessions()).sessions).toHaveLength(1);
            await expect(
                alice.createSession({
                    descriptor: utf8Encode("replayed KeyPackage claim"),
                    members: [replayed],
                }),
            ).rejects.toThrow("already used");
        } finally {
            alice.close();
            bob.close();
            await fixture.relay.close();
        }
    });

    test("ADV-10 prior-epoch traffic is capped at 64 messages and five minutes", async () => {
        let now = NOW;
        const fixture = relayFixture({}, () => now);
        const alice = await MurmurClient.open({
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        const bob = await MurmurClient.open({
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        try {
            const session = await alice.createSession({
                descriptor: utf8Encode("prior-epoch-adversarial"),
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.activateSession(session.id);

            for (let index = 0; index < 65; index += 1) {
                await bob.send(session.id, utf8Encode(`prior-${index}`));
            }
            await alice.setPolicies(session.id, {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            const boundedUpdates: MurmurUpdate[] = [];
            const bounded = await alice.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (batch) => {
                        boundedUpdates.push(...batch);
                    },
                },
            );
            expect(bounded.inbox.rejected).toBe(1);
            expect(
                boundedUpdates.filter((update) => utf8Decode(update.bytes).startsWith("prior-")),
            ).toHaveLength(64);

            await bob.send(session.id, utf8Encode("expired-prior"));
            await alice.setPolicies(session.id, {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: true,
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            now += 5 * MINUTE_MILLISECONDS + 1;
            await bob.synchronize({ waitMilliseconds: 0 });
            const expiredUpdates: MurmurUpdate[] = [];
            const expired = await alice.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (batch) => {
                        expiredUpdates.push(...batch);
                    },
                },
            );
            expect(expired.inbox.rejected).toBe(1);
            expect(expiredUpdates.map((update) => utf8Decode(update.bytes))).not.toContain(
                "expired-prior",
            );

            await bob.send(session.id, utf8Encode("current-after-prior-abuse"));
            await bob.synchronize({ waitMilliseconds: 0 });
            const current: MurmurUpdate[] = [];
            await alice.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (batch) => {
                        current.push(...batch);
                    },
                },
            );
            expect(current.map((update) => utf8Decode(update.bytes))).toContain(
                "current-after-prior-abuse",
            );
        } finally {
            alice.close();
            bob.close();
            await fixture.relay.close();
        }
    }, 120_000);

    test("ADV-11 provisioning and roster substitutions, replay, rollback, and revocation fail closed", () => {
        const account = generateIdentityKeyPair();
        const author = generateIdentityKeyPair();
        const device = generateIdentityKeyPair();
        const forkDevice = generateIdentityKeyPair();
        const material = createDeviceLinkMaterial(device, utf8Encode("key-package"), NOW);
        try {
            const roster = createInitialDeviceRoster(account, author, NOW, new Uint8Array(16));
            const authorization = authorizeDeviceProvisioning({
                request: material.request,
                account,
                authorDevice: author,
                roster,
                now: NOW + 1,
            });
            const requestBytes = serializeDeviceLinkRequest(material.request);
            const envelopeBytes = serializeProvisioningEnvelope(authorization.envelope);
            expect(parseDeviceLinkRequest(requestBytes, NOW)).toEqual(material.request);
            expect(parseProvisioningEnvelope(envelopeBytes)).toEqual(authorization.envelope);

            for (let replay = 0; replay < 1_000; replay += 1) {
                expect(parseProvisioningEnvelope(envelopeBytes).requestId).toEqual(
                    material.request.requestId,
                );
            }
            const completed = completeDeviceProvisioning(material, authorization.envelope, NOW + 2);
            expect(completed.account.publicKey).toEqual(account.publicKey);
            destroyIdentity(completed.account);
            expect(() =>
                completeDeviceProvisioning(
                    {
                        ...material,
                        request: {
                            ...material.request,
                            requestId: flip(material.request.requestId),
                        },
                    },
                    authorization.envelope,
                    NOW + 2,
                ),
            ).toThrow();
            expect(() =>
                completeDeviceProvisioning(
                    material,
                    { ...authorization.envelope, authorDeviceKey: forkDevice.publicKey },
                    NOW + 2,
                ),
            ).toThrow();
            expect(() =>
                completeDeviceProvisioning(
                    material,
                    authorization.envelope,
                    material.request.expiresAt,
                ),
            ).toThrow();
            for (const malformed of [
                flip(requestBytes),
                requestBytes.slice(0, -1),
                new Uint8Array(),
            ]) {
                expect(() => parseDeviceLinkRequest(malformed, NOW)).toThrow();
            }

            const left = addDeviceToRoster(
                roster,
                account,
                author,
                device.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(1),
            );
            const right = addDeviceToRoster(
                roster,
                account,
                author,
                forkDevice.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(2),
            );
            expect(selectDeviceRosterChild(left, [right])).toBeUndefined();
            const revoked = revokeDeviceFromRoster(
                left,
                account,
                author,
                device.publicKey,
                NOW + 2,
                new Uint8Array(16).fill(3),
            );
            expect(isActiveDevice(revoked, device.publicKey)).toBe(false);
            expect(() => parseDeviceRoster(flip(serializeDeviceRoster(revoked)))).toThrow();
        } finally {
            zeroBytes(material.ephemeralSecretKey);
            destroyIdentity(account);
            destroyIdentity(author);
            destroyIdentity(device);
            destroyIdentity(forkDevice);
        }
    });

    test("ADV-11 reset-announcement poison is terminal and cannot starve later session traffic", async () => {
        const fixture = relayFixture();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const attacker = generateIdentityKeyPair();
        const attackerAccount = generateIdentityKeyPair();
        const alice = await MurmurClient.open({
            identity: aliceIdentity,
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        const bob = await MurmurClient.open({
            identity: bobIdentity,
            transport: fixture.transport,
            store: new MemoryMurmurStore(),
            now: () => NOW,
        });
        try {
            const initialRoster = createInitialDeviceRoster(
                attackerAccount,
                attacker,
                NOW,
                new Uint8Array(16).fill(1),
            );
            const resetRoster = resetDeviceInRoster(
                initialRoster,
                attackerAccount,
                attacker,
                attacker.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(2),
            );
            expect(resetRoster.devices[0]).toMatchObject({ resetGeneration: 1 });
            const packet = encodeAccountSyncPacket({
                version: 1,
                type: "admission",
                roster: serializeDeviceRoster(resetRoster),
                keyPackage: utf8Encode("adversarial reset KeyPackage"),
            });
            expect(decodeAccountSyncPacket(packet)).toMatchObject({ type: "admission" });
            const packetJson = objectJson(packet);
            for (const malformed of [
                packet.slice(0, -1),
                utf8Encode(JSON.stringify({ ...packetJson, unknown: true })),
                utf8Encode(utf8Decode(packet).replace("{", '{"version":1,')),
            ]) {
                expect(() => decodeAccountSyncPacket(malformed)).toThrow();
            }

            const session = await alice.createSession({
                descriptor: utf8Encode("reset-announcement-adversarial"),
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.activateSession(session.id);

            await fixture.transport.publish(
                delivery(attacker, [bobIdentity.publicKey], new Uint8Array([5, 0x7b])),
            );
            await fixture.transport.publish(
                delivery(
                    attacker,
                    [bobIdentity.publicKey],
                    encodeAccountResetCiphertext({
                        ephemeralPublicKey: new Uint8Array(32),
                        nonce: new Uint8Array(12),
                        ciphertext: new Uint8Array(16),
                    }),
                ),
            );
            await alice.send(session.id, utf8Encode("valid-after-reset-poison"));
            await alice.synchronize({ waitMilliseconds: 0 });

            const updates: MurmurUpdate[] = [];
            const synchronized = await bob.synchronize(
                { waitMilliseconds: 0 },
                {
                    onUpdates: async (batch) => {
                        updates.push(...batch);
                    },
                },
            );
            expect(synchronized.inbox).toMatchObject({ processed: 1, rejected: 2 });
            expect(updates.map((update) => utf8Decode(update.bytes))).toEqual([
                "valid-after-reset-poison",
            ]);
            expect(await bob.session(session.id)).toMatchObject({ status: "active" });
        } finally {
            alice.close();
            bob.close();
            await closeFixture(fixture, [aliceIdentity, bobIdentity, attacker, attackerAccount]);
        }
    });

    test("ADV-12 private-group proof, group, replay, context, expiry, and encoding swaps fail closed", () => {
        const accountIdentifier = hashBytes(utf8Encode("private-account"));
        const otherIdentifier = hashBytes(utf8Encode("other-private-account"));
        const issuer = deriveCredentialIssuer(hashBytes(utf8Encode("issuer")));
        const groupA = derivePrivateGroupParameters(hashBytes(utf8Encode("group-a-parameters")));
        const groupB = derivePrivateGroupParameters(hashBytes(utf8Encode("group-b-parameters")));
        const issueContext = utf8Encode("credential issue revision 9");
        const presentationContext = utf8Encode("PATCH private roster revision 9");
        const expiresAt = NOW + 5 * MINUTE_MILLISECONDS;
        const state = createCredentialIssuanceRequest(
            accountIdentifier,
            issuer.publicParameters,
            issueContext,
        );
        const response = issueCredential({
            issuer,
            accountIdentifier,
            request: state.request,
            expiresAt,
            now: NOW,
            context: issueContext,
        });
        const credential = finalizeCredentialIssuance({
            state,
            response: decodeCredentialIssuanceResponse(encodeCredentialIssuanceResponse(response)),
            accountIdentifier,
            parameters: issuer.publicParameters,
            context: issueContext,
        });
        const encryptedUid = createEncryptedUid(accountIdentifier, groupA);
        const replayNonce = hashBytes(utf8Encode("private-replay"));
        const presentation = createUidPresentation({
            credential,
            accountIdentifier,
            encryptedUid,
            group: groupA,
            issuer: issuer.publicParameters,
            replayNonce,
            context: presentationContext,
            now: NOW,
        });
        const verify = (overrides: {
            readonly group?: ReturnType<typeof privateGroupPublicParameters>;
            readonly expectedReplayNonce?: Uint8Array;
            readonly context?: Uint8Array;
            readonly now?: number;
        }): boolean =>
            verifyUidPresentation({
                presentation,
                encryptedUid,
                group: overrides.group ?? privateGroupPublicParameters(groupA),
                issuer,
                expectedReplayNonce: overrides.expectedReplayNonce ?? replayNonce,
                context: overrides.context ?? presentationContext,
                now: overrides.now ?? NOW,
            });

        expect(verify({})).toBe(true);
        expect(verify({ group: privateGroupPublicParameters(groupB) })).toBe(false);
        expect(verify({ expectedReplayNonce: otherIdentifier })).toBe(false);
        expect(verify({ context: utf8Encode("GET private roster revision 9") })).toBe(false);
        expect(verify({ now: expiresAt })).toBe(false);
        expect(
            verifyUidPresentation({
                presentation: { ...presentation, proof: flip(presentation.proof) },
                encryptedUid,
                group: privateGroupPublicParameters(groupA),
                issuer,
                expectedReplayNonce: replayNonce,
                context: presentationContext,
                now: NOW,
            }),
        ).toBe(false);
        const encoded = encodeUidPresentation(presentation);
        expect(decodeUidPresentation(encoded)).toEqual(presentation);
        const decodedTampered = decodeUidPresentation(flip(encoded));
        expect(
            verifyUidPresentation({
                presentation: decodedTampered,
                encryptedUid,
                group: privateGroupPublicParameters(groupA),
                issuer,
                expectedReplayNonce: replayNonce,
                context: presentationContext,
                now: NOW,
            }),
        ).toBe(false);
        for (const malformed of [encoded.slice(0, -1), new Uint8Array()]) {
            expect(() => decodeUidPresentation(malformed)).toThrow();
        }
    });

    // PRODUCT FINDING: presentation challenges are one-use, but the resulting bearer token
    // currently authorizes unlimited reads until expiry. This sentinel turns red if replay is
    // bound or if the product explicitly adopts reusable bearer semantics and removes the test.
    test.fails("ADV-12 PRODUCT FINDING private-group access tokens reject replay before expiry", async () => {
        let now = NOW;
        const account = hashBytes(utf8Encode("token-replay-account"));
        const issuer = deriveCredentialIssuer(hashBytes(utf8Encode("token-replay-issuer")));
        const service = new PrivateGroupStateService({
            store: new SqlitePrivateGroupStateStore(":memory:"),
            credentialAuthority: createPrivateGroupCredentialAuthority(issuer),
            tokenSecret: hashBytes(utf8Encode("token-replay-service-secret")),
            now: () => now,
            tokenLifetimeMilliseconds: MINUTE_MILLISECONDS,
        });
        const client = new PrivateGroupStateClient({
            accountIdentifier: account,
            groupMasterSecret: hashBytes(utf8Encode("token-replay-group-secret")),
            transport: service,
            now: () => now,
        });
        const content: PrivateGroupRecordContent = {
            attributes: utf8Encode("token replay sentinel"),
            session: {
                id: hashBytes(utf8Encode("token-replay-session")),
                status: "active",
                descriptor: utf8Encode("token-replay-descriptor"),
                members: [account],
                owner: account,
                admins: [account],
                policies: { adminsAssignAdmins: false, anyoneCanAddMembers: false },
            },
            roles: [{ accountIdentifier: account, role: "owner" }],
        };
        try {
            const credential = await client.obtainCredential(utf8Encode("token replay auth"));
            await client.createGroup(credential, content);
            const token = await client.authorize(credential, "owner", "access");
            const outcomes: string[] = [];
            for (let attempt = 0; attempt < 2; attempt += 1) {
                try {
                    await service.readRecord({
                        opaqueGroupId: client.opaqueGroupId,
                        token: token.bytes,
                    });
                    outcomes.push("accepted");
                } catch {
                    outcomes.push("rejected");
                }
            }
            now = token.expiresAt;
            try {
                await service.readRecord({
                    opaqueGroupId: client.opaqueGroupId,
                    token: token.bytes,
                });
                outcomes.push("accepted");
            } catch {
                outcomes.push("rejected");
            }
            expect(outcomes).toEqual(["accepted", "rejected", "rejected"]);
        } finally {
            client.close();
            service.close();
        }
    });

    test("ADV-13 strict HTTP and response framing recovers after malformed inputs", async () => {
        const maximumJsonBodyBytes = 4_200;
        const fixture = relayFixture({
            maximumCiphertextBytes: 1,
            maximumRecipients: 1,
            maximumJsonBodyBytes,
        });
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const handler = createRelayFetchHandler(fixture.relay, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "http-adversarial",
        });
        try {
            const valid = delivery(sender, [recipient.publicKey], new Uint8Array([1]));
            const validJson = signedDeliveryToJson(valid);
            const malformedBodies = [
                "{",
                JSON.stringify({ ...validJson, unknown: true }),
                JSON.stringify({ ...validJson, sender: "not-base64url" }),
                JSON.stringify({ ...validJson, recipients: [] }),
                JSON.stringify({ ...validJson, ciphertext: "A===" }),
            ];
            for (const body of malformedBodies) {
                const response = await handler(
                    new Request("https://relay.test/v1/deliveries", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body,
                    }),
                );
                expect(response.status).toBeGreaterThanOrEqual(400);
            }
            const binary = await handler(
                new Request("https://relay.test/v1/deliveries", {
                    method: "POST",
                    headers: { "content-type": "application/octet-stream" },
                    body: new Uint8Array([0, 1, 2]),
                }),
            );
            expect(binary.status).toBeGreaterThanOrEqual(400);
            const declaredOversized = await handler(
                new Request("https://relay.test/v1/deliveries", {
                    method: "POST",
                    headers: {
                        "content-type": "application/json",
                        "content-length": String(maximumJsonBodyBytes + 1),
                    },
                    body: "{}",
                }),
            );
            expect(declaredOversized.status).toBe(413);

            const accepted = await handler(
                new Request("https://relay.test/v1/deliveries", {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify(validJson),
                }),
            );
            expect(accepted.status).toBe(200);
            expect(
                (
                    await fixture.transport.read(
                        createSignedInboxRead(recipient, { createdAt: NOW }),
                    )
                ).deliveries.map((queued) => queued.delivery.id),
            ).toEqual([valid.id]);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-13 WebSocket responses and streams reject oversize, truncation, binary, and pre-connect data", async () => {
        const identity = generateIdentityKeyPair();
        const page = {
            deliveries: [],
            head: STREAM_EVENT_ID,
            headSequence: 1,
            acknowledgedThrough: null,
            acknowledgedSequence: 0,
            generation: STREAM_GENERATION,
            exhausted: true,
        };
        const responseText = (id: string): string =>
            JSON.stringify({ version: 1, id, type: "response", status: 200, body: page });
        const exactBytes = utf8Encode(responseText("A".repeat(24))).length;
        const transport = (
            maximumMessageBytes: number,
            response: (valid: string) => unknown,
        ): WebSocketDeliveryTransport =>
            new WebSocketDeliveryTransport(identity, relaySessionProvider(), {
                now: () => NOW,
                maximumMessageBytes,
                webSocketFactory: () =>
                    new ScriptedWebSocket((frame, socket) => {
                        socket.receive(response(responseText(frame.id)));
                    }),
            });
        const read = createSignedInboxRead(identity, { createdAt: NOW, limit: 1 });
        try {
            await expect(transport(exactBytes, (valid) => valid).read(read)).resolves.toMatchObject(
                {
                    head: STREAM_EVENT_ID,
                    headSequence: 1,
                },
            );
            await expect(
                transport(exactBytes - 1, (valid) => valid).read(read),
            ).rejects.toMatchObject({ code: "invalid_response" });
            await expect(
                transport(exactBytes, (valid) => valid.slice(0, -1)).read(read),
            ).rejects.toMatchObject({ code: "invalid_response" });
            await expect(
                transport(exactBytes, (valid) => utf8Encode(valid)).read(read),
            ).rejects.toMatchObject({ code: "invalid_response" });

            await expect(transport(exactBytes, (valid) => valid).read(read)).resolves.toMatchObject(
                {
                    deliveries: [],
                    exhausted: true,
                },
            );

            const streamTransport = (
                script: (frame: WebSocketRequestFrame, socket: ScriptedWebSocket) => void,
            ): WebSocketDeliveryTransport =>
                new WebSocketDeliveryTransport(identity, relaySessionProvider(), {
                    now: () => NOW,
                    maximumMessageBytes: exactBytes,
                    webSocketFactory: () => new ScriptedWebSocket(script),
                });
            const streamRead = createSignedInboxRead(identity, {
                createdAt: NOW,
                limit: 1,
                waitMilliseconds: 0,
            });
            await expect(
                streamTransport((_frame, socket) => socket.receive("{"))
                    .stream(streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                streamTransport((_frame, socket) => socket.receive(new Uint8Array([1, 2, 3])))
                    .stream(streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                streamTransport((frame, socket) =>
                    socket.receive(
                        JSON.stringify({
                            version: 1,
                            id: frame.id,
                            type: "continuity",
                            body: page,
                        }),
                    ),
                )
                    .stream(streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                streamTransport((_frame, socket) => socket.receive("x".repeat(exactBytes + 1)))
                    .stream(streamRead)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });

            const live = streamTransport((frame, socket) => {
                socket.receive(
                    JSON.stringify({
                        version: 1,
                        id: frame.id,
                        type: "response",
                        status: 200,
                        body: { connected: true },
                    }),
                );
                queueMicrotask(() =>
                    socket.receive(
                        JSON.stringify({
                            version: 1,
                            id: frame.id,
                            type: "continuity",
                            body: {
                                generation: STREAM_GENERATION,
                                head: STREAM_EVENT_ID,
                                headSequence: 1,
                                acknowledgedThrough: null,
                                acknowledgedSequence: 0,
                            },
                        }),
                    ),
                );
            }).stream(streamRead);
            await expect(live.next()).resolves.toMatchObject({
                value: { type: "continuity", head: STREAM_EVENT_ID },
            });
            await live.return(undefined);
        } finally {
            destroyIdentity(identity);
        }
    });

    test("ADV-13 SSE frames enforce exact event bounds and reject truncation or invalid UTF-8", async () => {
        const identity = generateIdentityKeyPair();
        const event = utf8Encode(
            `event: continuity\ndata: ${JSON.stringify({
                generation: STREAM_GENERATION,
                head: STREAM_EVENT_ID,
                headSequence: 1,
                acknowledgedThrough: null,
                acknowledgedSequence: 0,
            })}\n\n`,
        );
        const request = createSignedInboxRead(identity, {
            createdAt: NOW,
            limit: 1,
            waitMilliseconds: 0,
        });
        const transport = (body: Uint8Array, maximumResponseBytes: number): HttpDeliveryTransport =>
            new HttpDeliveryTransport("https://relay.test", {
                maximumResponseBytes,
                fetch: async () =>
                    new Response(body.slice(), {
                        headers: { "content-type": "text/event-stream" },
                    }),
            });
        try {
            const exact = transport(event, event.length).stream(request);
            await expect(exact.next()).resolves.toMatchObject({
                done: false,
                value: { type: "continuity", headSequence: 1 },
            });
            await exact.return(undefined);

            await expect(
                transport(event, event.length - 1)
                    .stream(request)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                transport(event.slice(0, -1), event.length).stream(request).next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });
            await expect(
                transport(new Uint8Array([0xc3]), event.length)
                    .stream(request)
                    .next(),
            ).rejects.toMatchObject({ code: "invalid_stream" });

            const live = transport(event, event.length).stream(request);
            await expect(live.next()).resolves.toMatchObject({
                value: { type: "continuity", head: STREAM_EVENT_ID },
            });
            await live.return(undefined);
        } finally {
            destroyIdentity(identity);
        }
    });

    // PRODUCT FINDING: JSON.parse keeps the final duplicate field, so a hostile earlier value
    // is invisible to the relay's otherwise-exact object validation and can publish valid bytes.
    test.fails("ADV-13 PRODUCT FINDING HTTP rejects duplicate security fields atomically", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const handler = createRelayFetchHandler(fixture.relay, {
            requireRemoteAddress: false,
            defaultAdmissionPrincipal: "duplicate-field-adversarial",
        });
        try {
            const valid = delivery(sender, [recipient.publicKey], new Uint8Array([1]));
            const canonical = JSON.stringify(signedDeliveryToJson(valid));
            const duplicateBodies = [
                canonical.replace("{", '{"version":2,'),
                canonical.replace('"recipients":', '"recipients":[],"recipients":'),
                canonical.replace('"ciphertext":', '"ciphertext":"","ciphertext":'),
                canonical.replace('"signature":', '"signature":"AA","signature":'),
            ];
            const statuses: number[] = [];
            for (const body of duplicateBodies) {
                const response = await handler(
                    new Request("https://relay.test/v1/deliveries", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body,
                    }),
                );
                statuses.push(response.status);
            }
            const page = await fixture.transport.read(
                createSignedInboxRead(recipient, { createdAt: NOW }),
            );
            expect(statuses.every((status) => status >= 400)).toBe(true);
            expect(page.deliveries).toHaveLength(0);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    });

    test("ADV-14 1,000-way delivery and acknowledgement replay storms remain exact-once", async () => {
        const fixture = relayFixture();
        const sender = generateIdentityKeyPair();
        const recipient = generateIdentityKeyPair();
        const replayed = delivery(sender, [recipient.publicKey], utf8Encode("replayed"));
        const effects: string[] = [];
        const processor = new InboxProcessor(
            {
                identity: recipient,
                transport: fixture.transport,
                store: new MemoryMurmurStore(),
            },
            async (_transaction, queued) => {
                effects.push(queued.delivery.id);
            },
            { now: () => NOW },
        );
        try {
            let duplicates = 0;
            for (let replay = 0; replay < 1_000; replay += 1) {
                if ((await fixture.relay.publish(replayed, "replay-storm")).duplicate) {
                    duplicates += 1;
                }
            }
            expect(duplicates).toBe(999);
            await expect(processor.synchronize()).resolves.toMatchObject({ processed: 1 });
            expect(effects).toEqual([replayed.id]);
            const cursor = await processor.cursor();
            if (cursor === null) throw new Error("Missing replay-storm cursor");
            const ack = createSignedInboxAck(recipient, cursor, NOW);
            for (let replay = 0; replay < 1_000; replay += 1) {
                await expect(fixture.relay.acknowledge(ack)).resolves.toMatchObject({ removed: 0 });
            }
            await expect(processor.synchronize()).resolves.toMatchObject({ processed: 0 });
            expect(effects).toHaveLength(1);
        } finally {
            await closeFixture(fixture, [sender, recipient]);
        }
    }, 120_000);

    test("ADV-16 256 seeded structural mutations are deterministic and controls stay live", () => {
        const identity = generateIdentityKeyPair();
        const peer = generateIdentityKeyPair();
        const keyPackage = createMlsKeyPackage(identity, Math.floor(NOW / 1_000), 3_600);
        const discovery = serializeDiscoveryBundle(
            createDiscoveryBundle(identity, [keyPackage.keyPackage], {
                createdAt: NOW,
                expiresAt: NOW + MINUTE_MILLISECONDS,
            }),
        );
        const signed = delivery(identity, [peer.publicKey], utf8Encode("mutation-control"));
        const signedBytes = utf8Encode(JSON.stringify(signedDeliveryToJson(signed)));
        const link = createDeviceLinkMaterial(peer, utf8Encode("mutation-key-package"), NOW);
        const request = serializeDeviceLinkRequest(link.request);
        const roles = encodeSessionRoles({
            owner: identity.publicKey,
            admins: [peer.publicKey],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
        });
        const corpus = [
            {
                name: "discovery",
                bytes: discovery,
                parse: (value: Uint8Array): void => {
                    parseDiscoveryBundle(value, { now: NOW });
                },
            },
            {
                name: "delivery",
                bytes: signedBytes,
                parse: (value: Uint8Array): void => {
                    parseSignedDelivery(JSON.parse(utf8Decode(value)) as unknown);
                },
            },
            {
                name: "provisioning-request",
                bytes: request,
                parse: (value: Uint8Array): void => {
                    parseDeviceLinkRequest(value, NOW);
                },
            },
            {
                name: "role-control",
                bytes: roles,
                parse: (value: Uint8Array): void => {
                    decodeSessionRoles(value);
                },
            },
        ] as const;

        const campaign = (): readonly string[] => {
            const random = new SeededRandom(0x41445616);
            const trace: string[] = [];
            for (let seed = 0; seed < 256; seed += 1) {
                const artifact = corpus[random.integer(0, corpus.length)]!;
                const operator = random.integer(0, 4);
                let mutated: Uint8Array;
                if (operator === 0) {
                    mutated = artifact.bytes.slice(0, Math.max(0, artifact.bytes.length - 1));
                } else if (operator === 1) {
                    mutated = flip(artifact.bytes, random.integer(0, artifact.bytes.length));
                } else if (operator === 2) {
                    mutated = new Uint8Array([...artifact.bytes, random.integer(0, 256)]);
                } else {
                    mutated = new Uint8Array();
                }
                let outcome = "accepted";
                try {
                    artifact.parse(mutated);
                } catch {
                    outcome = "rejected";
                }
                trace.push(`${seed}:${artifact.name}:${operator}:${outcome}`);
            }
            return trace;
        };

        try {
            const first = campaign();
            const second = campaign();
            expect(second).toEqual(first);
            expect(first).toHaveLength(256);
            expect(first.join("\n").length).toBeLessThan(16 * 1_024);
            expect(first.filter((entry) => entry.endsWith(":rejected")).length).toBeGreaterThan(
                180,
            );
            for (let operation = 0; operation < 20; operation += 1) {
                const artifact = corpus[operation % corpus.length]!;
                expect(() => artifact.parse(artifact.bytes)).not.toThrow();
            }
        } finally {
            zeroBytes(link.ephemeralSecretKey);
            destroyMlsKeyPackageBundle(keyPackage);
            destroyIdentity(identity);
            destroyIdentity(peer);
        }
    });
});
