import {
    MemoryMurmurStore,
    decodeBase64Url,
    generateIdentityKeyPair,
    identityId,
    utf8Decode,
    utf8Encode,
    type IdentityKeyPair,
    type MurmurClient,
} from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import { mlsGroupTopic } from "../../groupChannel/index.js";
import { createMlsKeyPackage, destroyMlsKeyPackageBundle } from "../../keyPackage/index.js";
import {
    MAX_SHARED_SESSION_EPHEMERAL_BYTES,
    SHARED_SESSION_OWNER_MEMBER_ID,
    SharedSessionMember,
    SharedSessionOwner,
    type SharedSessionEphemeralChannel,
    type SharedSessionEphemeralDrop,
    type SharedSessionEphemeralEpochChange,
    type SharedSessionEphemeralFrame,
    type SharedSessionInvitation,
} from "../index.js";
import {
    LoopbackEphemeralRelay,
    MemoryRelayTransport,
    callbacks,
    captured,
    client,
    drain,
    emptySource,
    type Captured,
} from "./harness.js";

interface Party {
    readonly identity: IdentityKeyPair;
    readonly store: MemoryMurmurStore;
    readonly client: MurmurClient;
    readonly recorded: Captured;
}

function party(relay: MemoryRelayTransport): Party {
    const identity = generateIdentityKeyPair();
    const store = new MemoryMurmurStore();
    return { identity, store, client: client(identity, store, relay), recorded: captured() };
}

/** A share with one owner and one joined friend, ready to exchange frames. */
async function share(options: {
    readonly shareId: string;
    readonly relay: MemoryRelayTransport;
    readonly owner: Party;
    readonly friend: Party;
    readonly ownerControl?: boolean;
}): Promise<{
    readonly owner: SharedSessionOwner;
    readonly friend: SharedSessionMember;
    readonly bundle: ReturnType<typeof createMlsKeyPackage>;
}> {
    const invitations: SharedSessionInvitation[] = [];
    const bundle = createMlsKeyPackage(options.friend.identity);
    const owner = await SharedSessionOwner.create(options.shareId, {
        identity: options.owner.identity,
        client: options.owner.client,
        store: options.owner.store,
        callbacks: callbacks(options.owner.recorded, options.ownerControl ?? true),
        entrySource: emptySource(),
        invitationDelivery: {
            deliver: async (invitation) => {
                invitations.push(invitation);
            },
        },
    });
    await owner.invite({ identity: options.friend.identity, keyPackage: bundle.keyPackage });
    const friend = await SharedSessionMember.join({
        identity: options.friend.identity,
        client: options.friend.client,
        store: options.friend.store,
        callbacks: callbacks(options.friend.recorded),
        invitation: invitations[0]!.text,
        keyPackageBundle: bundle,
        expectedOwner: options.owner.identity,
    });
    await drain(options.owner.client, owner);
    await drain(options.friend.client, friend);
    return { owner, friend, bundle };
}

function collect(channel: SharedSessionEphemeralChannel): {
    readonly frames: SharedSessionEphemeralFrame[];
    readonly drops: SharedSessionEphemeralDrop[];
    readonly epochChanges: SharedSessionEphemeralEpochChange[];
} {
    const frames: SharedSessionEphemeralFrame[] = [];
    const drops: SharedSessionEphemeralDrop[] = [];
    const epochChanges: SharedSessionEphemeralEpochChange[] = [];
    channel.onReceived((frame) => frames.push(frame));
    channel.onDropped((drop) => drops.push(drop));
    channel.onEpochChanged((change) => epochChanges.push(change));
    return { frames, drops, epochChanges };
}

/** Let the channel's outbound pump drain completely. */
async function settle(): Promise<void> {
    for (let index = 0; index < 5; index += 1) {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
}

describe("shared session ephemeral channel", () => {
    it("carries authenticated frames in both directions under the current epoch", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_basic",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        const ownerSeen = collect(ownerChannel);
        const friendSeen = collect(friendChannel);

        friendChannel.send(utf8Encode("ls -la\n"));
        ownerChannel.send(utf8Encode("total 0\n"));
        await settle();

        expect(ownerSeen.frames).toHaveLength(1);
        expect(utf8Decode(ownerSeen.frames[0]!.bytes)).toBe("ls -la\n");
        expect(ownerSeen.frames[0]!.authenticatedPeerId).toBe(identityId(friendParty.identity));
        expect(ownerSeen.frames[0]!.grantEpoch).toBe(1);
        expect(ownerSeen.frames[0]!.shareMemberId).toBe(owner.state.members[0]!.shareMemberId);

        expect(friendSeen.frames).toHaveLength(1);
        expect(utf8Decode(friendSeen.frames[0]!.bytes)).toBe("total 0\n");
        expect(friendSeen.frames[0]!.shareMemberId).toBe(SHARED_SESSION_OWNER_MEMBER_ID);
        expect(ownerSeen.drops).toEqual([]);
        expect(friendSeen.drops).toEqual([]);

        ownerChannel.close();
        friendChannel.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("never writes an ephemeral frame to the durable store or the transcript", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_not_durable",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        const ownerSeen = collect(ownerChannel);

        const ownerKeysBefore = [...(await ownerParty.store.list("")).keys()];
        const friendKeysBefore = [...(await friendParty.store.list("")).keys()];
        const relayEventsBefore = relay
            .events(mlsGroupTopic(decodeBase64Url(owner.state.groupId)))
            .map((event) => event.id);

        for (let index = 0; index < 32; index += 1) {
            friendChannel.send(utf8Encode(`frame-${index.toString()}`));
        }
        await settle();
        expect(ownerSeen.frames).toHaveLength(32);

        expect([...(await ownerParty.store.list("")).keys()]).toEqual(ownerKeysBefore);
        expect([...(await friendParty.store.list("")).keys()]).toEqual(friendKeysBefore);
        expect(
            relay
                .events(mlsGroupTopic(decodeBase64Url(owner.state.groupId)))
                .map((event) => event.id),
        ).toEqual(relayEventsBefore);
        expect(ownerParty.recorded.entries).toEqual([]);
        expect(ownerParty.recorded.posts).toEqual([]);
        expect(ownerParty.recorded.controls).toEqual([]);

        // A durable sync afterwards must still find nothing new.
        await drain(ownerParty.client, owner);
        expect(ownerParty.recorded.entries).toEqual([]);

        ownerChannel.close();
        friendChannel.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("drops the oldest frames for a stalled peer instead of buffering them", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_backpressure",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const friendChannel = friend.openEphemeralChannel({
            transport: fanout.transportFor(),
            maximumQueuedFrames: 4,
        });
        const ownerSeen = collect(ownerChannel);
        const friendSeen = collect(friendChannel);

        fanout.hold();
        for (let index = 0; index < 40; index += 1) {
            friendChannel.send(utf8Encode(`frame-${index.toString().padStart(2, "0")}`));
        }
        const overflow = friendSeen.drops
            .filter((drop) => drop.reason === "queue-overflow")
            .reduce((total, drop) => total + drop.frames, 0);
        expect(overflow).toBeGreaterThan(0);
        fanout.release();
        await settle();

        // One frame was in flight plus at most the bounded queue.
        expect(ownerSeen.frames.length).toBeLessThanOrEqual(6);
        expect(ownerSeen.frames.length + overflow).toBe(40);
        // The surviving frames are the newest ones, still in sender order.
        const texts = ownerSeen.frames.map((frame) => utf8Decode(frame.bytes));
        expect(texts).toEqual([...texts].sort());
        expect(texts.at(-1)).toBe("frame-39");

        ownerChannel.close();
        friendChannel.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("preserves per-sender order across two concurrent friends", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const firstParty = party(relay);
        const secondParty = party(relay);
        const invitations: SharedSessionInvitation[] = [];
        const firstBundle = createMlsKeyPackage(firstParty.identity);
        const secondBundle = createMlsKeyPackage(secondParty.identity);
        const owner = await SharedSessionOwner.create("share_ephemeral_order", {
            identity: ownerParty.identity,
            client: ownerParty.client,
            store: ownerParty.store,
            callbacks: callbacks(ownerParty.recorded),
            entrySource: emptySource(),
            invitationDelivery: {
                deliver: async (invitation) => {
                    invitations.push(invitation);
                },
            },
        });
        await owner.inviteMany([
            { identity: firstParty.identity, keyPackage: firstBundle.keyPackage },
            { identity: secondParty.identity, keyPackage: secondBundle.keyPackage },
        ]);
        const first = await SharedSessionMember.join({
            identity: firstParty.identity,
            client: firstParty.client,
            store: firstParty.store,
            callbacks: callbacks(firstParty.recorded),
            invitation: invitations.find(
                (invitation) =>
                    identityId(invitation.recipient) === identityId(firstParty.identity),
            )!.text,
            keyPackageBundle: firstBundle,
            expectedOwner: ownerParty.identity,
        });
        const second = await SharedSessionMember.join({
            identity: secondParty.identity,
            client: secondParty.client,
            store: secondParty.store,
            callbacks: callbacks(secondParty.recorded),
            invitation: invitations.find(
                (invitation) =>
                    identityId(invitation.recipient) === identityId(secondParty.identity),
            )!.text,
            keyPackageBundle: secondBundle,
            expectedOwner: ownerParty.identity,
        });
        await drain(ownerParty.client, owner);
        await drain(firstParty.client, first);
        await drain(secondParty.client, second);

        const ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const firstChannel = first.openEphemeralChannel({ transport: fanout.transportFor() });
        const secondChannel = second.openEphemeralChannel({ transport: fanout.transportFor() });
        const ownerSeen = collect(ownerChannel);

        for (let index = 0; index < 5; index += 1) {
            firstChannel.send(utf8Encode(`first-${index.toString()}`));
            secondChannel.send(utf8Encode(`second-${index.toString()}`));
        }
        await settle();

        const bySender = new Map<string, string[]>();
        for (const frame of ownerSeen.frames) {
            const texts = bySender.get(frame.authenticatedPeerId) ?? [];
            texts.push(utf8Decode(frame.bytes));
            bySender.set(frame.authenticatedPeerId, texts);
        }
        expect(bySender.get(identityId(firstParty.identity))).toEqual([
            "first-0",
            "first-1",
            "first-2",
            "first-3",
            "first-4",
        ]);
        expect(bySender.get(identityId(secondParty.identity))).toEqual([
            "second-0",
            "second-1",
            "second-2",
            "second-3",
            "second-4",
        ]);

        ownerChannel.close();
        firstChannel.close();
        secondChannel.close();
        owner.destroy();
        first.destroy();
        second.destroy();
        destroyMlsKeyPackageBundle(firstBundle);
        destroyMlsKeyPackageBundle(secondBundle);
    });

    it("survives hostile bytes injected into the topic", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_hostile",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        const ownerSeen = collect(ownerChannel);
        const topic = mlsGroupTopic(decodeBase64Url(owner.state.groupId));

        // Anyone who learns the topic can publish: the relay authenticates
        // nothing. None of this may surface, and none of it may fault the
        // stream that carries real frames.
        const wellFormedHeader = new Uint8Array(36);
        wellFormedHeader[0] = 1;
        wellFormedHeader[1] = 1;
        wellFormedHeader.fill(0xff, 2, 10);
        // Claim the friend's leaf, whose signature key the owner does know.
        wellFormedHeader[11] = 1;
        const hostile = [
            new Uint8Array(0),
            new Uint8Array(7).fill(0xff),
            new Uint8Array(36 + 64).fill(0xaa),
            wellFormedHeader,
            new Uint8Array([...wellFormedHeader, ...new Uint8Array(64).fill(3)]),
            new Uint8Array(MAX_SHARED_SESSION_EPHEMERAL_BYTES * 2).fill(0x5a),
        ];
        for (const bytes of hostile) {
            fanout.inject(topic, bytes);
        }
        await settle();

        expect(ownerSeen.frames).toHaveLength(0);
        // Nothing unauthenticated is allowed to claim an epoch.
        expect(ownerSeen.epochChanges).toHaveLength(0);
        expect(ownerSeen.drops.length).toBeGreaterThanOrEqual(hostile.length);

        // The channel is still live and still carries a real frame.
        friendChannel.send(utf8Encode("still here"));
        await settle();
        expect(ownerSeen.frames).toHaveLength(1);
        expect(utf8Decode(ownerSeen.frames[0]!.bytes)).toBe("still here");

        ownerChannel.close();
        friendChannel.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("closes in-flight ephemeral traffic on a revoke commit", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_revoke",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        const ownerSeen = collect(ownerChannel);
        const friendSeen = collect(friendChannel);
        const epochBefore = ownerChannel.epoch;

        friendChannel.send(utf8Encode("before"));
        await settle();
        expect(ownerSeen.frames).toHaveLength(1);

        await owner.revoke(friendParty.identity);
        await settle();

        // The owner rekeyed immediately, without waiting for a durable sync.
        expect(ownerChannel.epoch).toBeGreaterThan(epochBefore);
        expect(ownerSeen.epochChanges.some((change) => change.reason === "local-commit")).toBe(
            true,
        );

        // The revoked friend still holds the old epoch, so nothing it sends
        // can be opened, and the owner's own frames are equally unreadable.
        friendChannel.send(utf8Encode("after"));
        ownerChannel.send(utf8Encode("owner-after"));
        await settle();
        expect(ownerSeen.frames).toHaveLength(1);
        // The Commit blanked the friend's leaf, so the owner rejects what it
        // sends on identity, before the epoch is ever considered.
        expect(ownerSeen.drops.some((drop) => drop.reason === "unknown-sender")).toBe(true);
        expect(friendSeen.frames).toHaveLength(0);
        expect(friendSeen.epochChanges.some((change) => change.reason === "peer-ahead")).toBe(true);

        ownerChannel.close();
        friendChannel.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("closes the channel when the member replica is removed", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_removed",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        expect(friendChannel.open).toBe(true);

        await owner.revoke(friendParty.identity);
        await drain(friendParty.client, friend);

        expect(friendChannel.open).toBe(false);
        expect(fanout.subscribers(mlsGroupTopic(decodeBase64Url(owner.state.groupId)))).toBe(0);
        expect(() => friendChannel.send(utf8Encode("nope"))).toThrowError(/closed/);

        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("resumes after the relay stream drops and reconnects", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_reconnect",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        let ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        let ownerSeen = collect(ownerChannel);

        friendChannel.send(utf8Encode("first"));
        await settle();
        expect(ownerSeen.frames).toHaveLength(1);

        // The relay drops every stream; frames sent meanwhile are simply lost.
        fanout.disconnect();
        friendChannel.send(utf8Encode("lost"));
        await settle();
        expect(ownerSeen.frames).toHaveLength(1);

        ownerChannel.close();
        ownerChannel = owner.openEphemeralChannel({ transport: fanout.transportFor() });
        ownerSeen = collect(ownerChannel);
        friendChannel.close();
        const resumedFriend = friend.openEphemeralChannel({ transport: fanout.transportFor() });
        resumedFriend.send(utf8Encode("resumed"));
        await settle();

        expect(ownerSeen.frames.map((frame) => utf8Decode(frame.bytes))).toEqual(["resumed"]);

        ownerChannel.close();
        resumedFriend.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("bounds one frame and refuses to send without an active grant", async () => {
        const relay = new MemoryRelayTransport();
        const fanout = new LoopbackEphemeralRelay();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_ephemeral_bounds",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });
        const friendChannel = friend.openEphemeralChannel({ transport: fanout.transportFor() });

        expect(() =>
            friendChannel.send(new Uint8Array(MAX_SHARED_SESSION_EPHEMERAL_BYTES + 1)),
        ).toThrowError(/exceeds/);
        expect(() =>
            friendChannel.send(new Uint8Array(MAX_SHARED_SESSION_EPHEMERAL_BYTES)),
        ).not.toThrow();

        friendChannel.close();
        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });
});

describe("shared session friend control", () => {
    it("delivers typed control to the owner, separately from posts", async () => {
        const relay = new MemoryRelayTransport();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_control_basic",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });

        const control = await friend.sendControl(
            "control-1",
            { kind: "request-capability", capability: "terminal", nested: [1, true, null] },
            77,
        );
        await drain(ownerParty.client, owner);

        expect(ownerParty.recorded.controls).toEqual([
            {
                shareId: "share_control_basic",
                authenticatedPeerId: identityId(friendParty.identity),
                shareMemberId: owner.state.members[0]!.shareMemberId,
                grantEpoch: 1,
                controlId: "control-1",
                timestamp: 77,
                payload: {
                    kind: "request-capability",
                    capability: "terminal",
                    nested: [1, true, null],
                },
            },
        ]);
        expect(ownerParty.recorded.posts).toEqual([]);
        expect(control.authenticatedPeerId).toBe(identityId(friendParty.identity));

        // A replayed control frame is committed exactly once.
        await drain(ownerParty.client, owner);
        expect(ownerParty.recorded.controls).toHaveLength(1);

        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("quarantines friend control when the owner accepts none", async () => {
        const relay = new MemoryRelayTransport();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_control_absent",
            relay,
            owner: ownerParty,
            friend: friendParty,
            ownerControl: false,
        });

        await friend.sendControl("control-1", { kind: "request-capability" }, 5);
        const sync = await ownerParty.client.sync();
        if (sync.status !== "events") {
            throw new Error("unexpected reset");
        }
        const results = [];
        for (const event of sync.events) {
            results.push(await owner.handleEvent(event));
        }

        expect(results.some((result) => result.status === "quarantined")).toBe(true);
        expect(ownerParty.recorded.controls).toEqual([]);
        expect(ownerParty.recorded.posts).toEqual([]);
        expect(ownerParty.recorded.terminations).toEqual([]);

        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });

    it("refuses control from a revoked grant", async () => {
        const relay = new MemoryRelayTransport();
        const ownerParty = party(relay);
        const friendParty = party(relay);
        const { owner, friend, bundle } = await share({
            shareId: "share_control_revoked",
            relay,
            owner: ownerParty,
            friend: friendParty,
        });

        await owner.revoke(friendParty.identity);
        await drain(friendParty.client, friend);

        await expect(friend.sendControl("control-1", { kind: "late" }, 5)).rejects.toThrowError();
        expect(ownerParty.recorded.controls).toEqual([]);

        owner.destroy();
        friend.destroy();
        destroyMlsKeyPackageBundle(bundle);
    });
});
