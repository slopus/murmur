import {
    MemoryMurmurStore,
    MurmurClient,
    canonicalJsonBytes,
    createRelayBlob,
    createRelayEvent,
    decodeBase64Url,
    encodeBase64Url,
    equalRelayEvents,
    generateIdentityKeyPair,
    identityId,
    verifyRelayBlob,
    type EventPage,
    type ListPage,
    type PublishOutcome,
    type RelayBlob,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicState,
} from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import { createMlsKeyPackage, destroyMlsKeyPackageBundle } from "../../keyPackage/index.js";
import { decodeMlsTreeCommit, encodeMlsTreeCommit } from "../../commit/index.js";
import { mlsGroupTopic } from "../../groupChannel/index.js";
import {
    SharedSessionMember,
    SharedSessionOwner,
    SharedSessionProtocolError,
    type SessionEntrySource,
    type SharedSessionCallbacks,
    type SharedSessionEntry,
    type SharedSessionInvitation,
    type SharedSessionPost,
    type SharedSessionState,
} from "../index.js";
import { decodeSharedSessionFrame } from "../impl/frameCodec.js";

class MemoryRelayTransport implements RelayTransport {
    readonly id = "memory";
    readonly #events = new Map<string, SignedRelayEvent[]>();
    readonly #blobs = new Map<string, Uint8Array>();

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        const events = this.#events.get(event.topic) ?? [];
        const prior = events.find((candidate) => candidate.id === event.id);
        if (prior !== undefined) {
            if (!equalRelayEvents(prior, event)) {
                throw new Error("event collision");
            }
            return {
                seq: BigInt(events.indexOf(prior) + 1),
                duplicate: true,
            };
        }
        events.push(event);
        this.#events.set(event.topic, events);
        return { seq: BigInt(events.length), duplicate: false };
    }

    async readState(topic: string): Promise<TopicState | undefined> {
        const events = this.#events.get(topic) ?? [];
        return {
            seq: BigInt(events.length),
            snapshot: null,
            list: { elements: [], nextCursor: null },
        };
    }

    async readList(): Promise<ListPage | undefined> {
        return { elements: [], nextCursor: null };
    }

    async readEvents(topic: string, since: bigint, limit: number = 100): Promise<EventPage> {
        const events = this.#events.get(topic) ?? [];
        const start = Number(since);
        return {
            events: events.slice(start, start + limit).map((event, index) => ({
                seq: BigInt(start + index + 1),
                event,
            })),
            reset: false,
            seq: BigInt(events.length),
        };
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        if (!verifyRelayBlob(blob)) {
            throw new Error("invalid blob");
        }
        this.#blobs.set(blob.id, blob.bytes.slice());
    }

    async getBlob(id: string, expectedBytes?: number): Promise<RelayBlob | undefined> {
        const bytes = this.#blobs.get(id);
        if (bytes === undefined) {
            return undefined;
        }
        if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
            throw new Error("blob size mismatch");
        }
        return createRelayBlob(bytes);
    }

    events(topic: string): readonly SignedRelayEvent[] {
        return [...(this.#events.get(topic) ?? [])];
    }
}

interface Captured {
    readonly entries: SharedSessionEntry[];
    readonly states: SharedSessionState[];
    readonly posts: SharedSessionPost[];
    readonly terminations: string[];
}

function callbacks(captured: Captured): SharedSessionCallbacks {
    return {
        persistEntry: async (_transaction, entry) => {
            captured.entries.push(entry);
        },
        persistState: async (_transaction, state) => {
            captured.states.push(state);
        },
        persistPost: async (_transaction, post) => {
            captured.posts.push(post);
        },
        terminate: async (_transaction, termination) => {
            captured.terminations.push(termination.reason);
        },
    };
}

function captured(): Captured {
    return { entries: [], states: [], posts: [], terminations: [] };
}

function emptySource(): SessionEntrySource {
    return {
        readPage: async () => ({ entries: [], done: true }),
    };
}

function client(
    identity: ReturnType<typeof generateIdentityKeyPair>,
    store: MemoryMurmurStore,
    relay: RelayTransport,
): MurmurClient {
    return new MurmurClient({ identity, store, transports: [relay] });
}

async function drain(
    murmur: MurmurClient,
    session: Pick<SharedSessionMember | SharedSessionOwner, "handleEvent">,
): Promise<void> {
    const sync = await murmur.sync();
    if (sync.status !== "events") {
        throw new Error("unexpected reset");
    }
    for (const event of sync.events) {
        await session.handleEvent(event);
    }
}

const entryOne = {
    shareSequence: 1,
    shareEventId: "018f1d5e-7b00-7000-8000-000000000001",
    timestamp: 1,
    payload: {
        version: 7,
        role: "tool",
        nested: { full: ["opaque", true, null] },
    },
} as const;

describe("shared agent sessions", () => {
    it("classifies malformed authenticated post frames as typed protocol faults", () => {
        const ownerIdentity = generateIdentityKeyPair();
        const malformed = canonicalJsonBytes({
            grantEpoch: 0,
            groupId: encodeBase64Url(ownerIdentity.signingKey),
            kind: "post",
            postId: "caller-post-invalid",
            shareId: "share_invalid_post",
            text: "peer controlled",
            timestamp: 1,
            version: 1,
        });
        expect(() => decodeSharedSessionFrame(malformed, ownerIdentity)).toThrowError(
            SharedSessionProtocolError,
        );
    });

    it("starts two friends in one batch and carries opaque owner entries", async () => {
        const relay = new MemoryRelayTransport();
        const ownerIdentity = generateIdentityKeyPair();
        const aliceIdentity = generateIdentityKeyPair();
        const bobIdentity = generateIdentityKeyPair();
        const ownerStore = new MemoryMurmurStore();
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const ownerClient = client(ownerIdentity, ownerStore, relay);
        const aliceClient = client(aliceIdentity, aliceStore, relay);
        const bobClient = client(bobIdentity, bobStore, relay);
        const ownerCaptured = captured();
        const aliceCaptured = captured();
        const bobCaptured = captured();
        const invitations: SharedSessionInvitation[] = [];
        const aliceBundle = createMlsKeyPackage(aliceIdentity);
        const bobBundle = createMlsKeyPackage(bobIdentity);

        const owner = await SharedSessionOwner.create("share_cuid2_alpha", {
            identity: ownerIdentity,
            client: ownerClient,
            store: ownerStore,
            callbacks: callbacks(ownerCaptured),
            entrySource: emptySource(),
            invitationDelivery: {
                deliver: async (invitation) => {
                    invitations.push(invitation);
                },
            },
            now: () => 100,
        });
        const result = await owner.inviteMany([
            { identity: aliceIdentity, keyPackage: aliceBundle.keyPackage },
            { identity: bobIdentity, keyPackage: bobBundle.keyPackage },
        ]);

        expect(result.state.stateSequence).toBe(1);
        expect(result.state.members).toHaveLength(2);
        expect(invitations).toHaveLength(2);
        expect(new Set(result.state.members.map((member) => member.grantEpoch))).toEqual(
            new Set([1]),
        );

        const aliceInvitation = invitations.find(
            (invitation) => identityId(invitation.recipient) === identityId(aliceIdentity),
        )!;
        const bobInvitation = invitations.find(
            (invitation) => identityId(invitation.recipient) === identityId(bobIdentity),
        )!;
        let alice = await SharedSessionMember.join({
            identity: aliceIdentity,
            client: aliceClient,
            store: aliceStore,
            callbacks: callbacks(aliceCaptured),
            invitation: aliceInvitation.text,
            keyPackageBundle: aliceBundle,
            expectedOwner: ownerIdentity,
        });
        const bob = await SharedSessionMember.join({
            identity: bobIdentity,
            client: bobClient,
            store: bobStore,
            callbacks: callbacks(bobCaptured),
            invitation: bobInvitation.text,
            keyPackageBundle: bobBundle,
            expectedOwner: ownerIdentity,
        });
        await drain(aliceClient, alice);
        await drain(bobClient, bob);
        await drain(ownerClient, owner);

        await owner.append(entryOne);
        await drain(aliceClient, alice);
        await drain(bobClient, bob);

        expect(aliceCaptured.entries).toEqual([
            expect.objectContaining({
                shareSequence: 1,
                shareEventId: entryOne.shareEventId,
                payload: entryOne.payload,
            }),
        ]);
        expect(bobCaptured.entries).toEqual(aliceCaptured.entries);
        expect(alice.state.groupId).toBe(owner.state.groupId);
        expect(bob.state.ownerId).toBe(identityId(ownerIdentity));

        const stableMemberId = alice.state.members.find(
            (member) => member.peerId === identityId(aliceIdentity),
        )!.shareMemberId;
        await owner.revoke(aliceIdentity);
        await drain(aliceClient, alice);
        await drain(bobClient, bob);
        expect(aliceCaptured.terminations).toEqual(["ended"]);

        const aliceReaddBundle = createMlsKeyPackage(aliceIdentity);
        await owner.invite({
            identity: aliceIdentity,
            keyPackage: aliceReaddBundle.keyPackage,
        });
        const readdInvitation = invitations.at(-1)!;
        alice = await SharedSessionMember.join({
            identity: aliceIdentity,
            client: aliceClient,
            store: aliceStore,
            callbacks: callbacks(aliceCaptured),
            invitation: readdInvitation.text,
            keyPackageBundle: aliceReaddBundle,
            expectedOwner: ownerIdentity,
        });
        await drain(aliceClient, alice);
        const readdedGrant = alice.state.members.find(
            (member) => member.peerId === identityId(aliceIdentity),
        )!;
        expect(readdedGrant).toMatchObject({
            shareMemberId: stableMemberId,
            grantEpoch: 2,
            status: "active",
        });

        const stopped = await owner.stop();
        expect(stopped.status).toBe("stopped");
        await drain(aliceClient, alice);
        await drain(bobClient, bob);
        expect(aliceCaptured.terminations).toEqual(["ended", "ended"]);
        expect(bobCaptured.terminations).toEqual(["ended"]);

        alice.destroy();
        bob.destroy();
        destroyMlsKeyPackageBundle(aliceBundle);
        destroyMlsKeyPackageBundle(aliceReaddBundle);
        destroyMlsKeyPackageBundle(bobBundle);
    });

    it("backfills encrypted history across restart and authenticates friend posts", async () => {
        const relay = new MemoryRelayTransport();
        const ownerIdentity = generateIdentityKeyPair();
        const friendIdentity = generateIdentityKeyPair();
        const ownerStore = new MemoryMurmurStore();
        const friendStore = new MemoryMurmurStore();
        const ownerClient = client(ownerIdentity, ownerStore, relay);
        const friendClient = client(friendIdentity, friendStore, relay);
        const ownerCaptured = captured();
        const friendCaptured = captured();
        let invitation: SharedSessionInvitation | undefined;
        const bundle = createMlsKeyPackage(friendIdentity);
        const source: SessionEntrySource = {
            readPage: async ({ afterSequence }) =>
                afterSequence === 0
                    ? { entries: [entryOne], done: true }
                    : { entries: [], done: true },
        };
        const ownerOptions = {
            identity: ownerIdentity,
            client: ownerClient,
            store: ownerStore,
            callbacks: callbacks(ownerCaptured),
            entrySource: source,
            invitationDelivery: {
                deliver: async (value: SharedSessionInvitation) => {
                    invitation = value;
                },
            },
        };
        const owner = await SharedSessionOwner.create("share_cuid2_history", ownerOptions);
        await owner.invite({ identity: friendIdentity, keyPackage: bundle.keyPackage });
        const friendOptions = {
            identity: friendIdentity,
            client: friendClient,
            store: friendStore,
            callbacks: callbacks(friendCaptured),
        };
        let friend = await SharedSessionMember.join({
            ...friendOptions,
            invitation: invitation!.text,
            keyPackageBundle: bundle,
            expectedOwner: ownerIdentity,
        });
        await drain(friendClient, friend);
        const joinedRetry = await friend.retry();
        expect(joinedRetry.failures).toEqual([]);
        friend.destroy();

        friend = await SharedSessionMember.load("share_cuid2_history", friendOptions);
        for (let index = 0; index < 5; index += 1) {
            const retry = await friend.retry();
            expect(retry.failures).toEqual([]);
        }
        expect(friendCaptured.entries).toEqual([
            expect.objectContaining({ shareSequence: 1, payload: entryOne.payload }),
        ]);

        await drain(ownerClient, owner);
        await friend.post("caller-post-1", "hello owner", 50);
        await drain(ownerClient, owner);
        expect(ownerCaptured.posts).toEqual([
            expect.objectContaining({
                authenticatedPeerId: identityId(friendIdentity),
                postId: "caller-post-1",
                text: "hello owner",
                grantEpoch: 1,
            }),
        ]);

        await owner.append({
            shareSequence: 2,
            shareEventId: "018f1d5e-7b00-7000-8000-000000000002",
            timestamp: 51,
            payload: {
                version: 7,
                kind: "friend-post",
                postId: "caller-post-1",
                text: "hello owner",
            },
        });
        await drain(friendClient, friend);
        expect(friendCaptured.entries.at(-1)).toMatchObject({
            shareSequence: 2,
            payload: { kind: "friend-post", postId: "caller-post-1" },
        });

        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("defers a structurally valid but unauthenticated forged Commit", async () => {
        const relay = new MemoryRelayTransport();
        const ownerIdentity = generateIdentityKeyPair();
        const friendIdentity = generateIdentityKeyPair();
        const attackerIdentity = generateIdentityKeyPair();
        const ownerStore = new MemoryMurmurStore();
        const friendStore = new MemoryMurmurStore();
        const ownerClient = client(ownerIdentity, ownerStore, relay);
        const friendClient = client(friendIdentity, friendStore, relay);
        const ownerCaptured = captured();
        const friendCaptured = captured();
        let invitation: SharedSessionInvitation | undefined;
        const bundle = createMlsKeyPackage(friendIdentity);
        const owner = await SharedSessionOwner.create("share_forged_commit", {
            identity: ownerIdentity,
            client: ownerClient,
            store: ownerStore,
            callbacks: callbacks(ownerCaptured),
            entrySource: emptySource(),
            invitationDelivery: {
                deliver: async (value) => {
                    invitation = value;
                },
            },
        });
        const friend = await SharedSessionMember.join({
            identity: friendIdentity,
            client: friendClient,
            store: friendStore,
            callbacks: callbacks(friendCaptured),
            invitation: (
                await owner.invite({
                    identity: friendIdentity,
                    keyPackage: bundle.keyPackage,
                })
            ).invitations[0]!.text,
            keyPackageBundle: bundle,
            expectedOwner: ownerIdentity,
        });
        expect(invitation).toBeDefined();
        await drain(ownerClient, owner);
        await drain(friendClient, friend);

        const topic = mlsGroupTopic(decodeBase64Url(owner.groupId));
        const originalCommit = relay.events(topic)[0]!;
        const parsed = decodeMlsTreeCommit(originalCommit.payload);
        const forgedPayload = encodeMlsTreeCommit({
            ...parsed,
            sender: 1,
        });
        await relay.publish(createRelayEvent(attackerIdentity, topic, forgedPayload));
        const sync = await ownerClient.sync();
        expect(sync.status).toBe("events");
        if (sync.status !== "events") {
            throw new Error("unexpected reset");
        }
        expect(sync.events).toHaveLength(1);
        await expect(owner.handleEvent(sync.events[0]!)).resolves.toEqual({
            status: "deferred",
        });
        expect(ownerCaptured.terminations).toEqual([]);

        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });
});
