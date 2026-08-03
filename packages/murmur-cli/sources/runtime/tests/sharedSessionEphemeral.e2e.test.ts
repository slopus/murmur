import {
    SharedSessionMember,
    SharedSessionOwner,
    type SessionEntrySource,
    type SharedSessionCallbacks,
    type SharedSessionControl,
    type SharedSessionEphemeralFrame,
    type SharedSessionInvitation,
    type SharedSessionPost,
    type SharedSessionState,
} from "@murmur/mls";
import { createMlsKeyPackage, destroyMlsKeyPackageBundle } from "@murmur/mls";
import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@murmur/relay";
import {
    HttpRelayTransport,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    identityId,
    utf8Decode,
    utf8Encode,
    type IdentityKeyPair,
    type StoreTransaction,
} from "@slopus/murmur";
import { afterEach, describe, expect, it } from "vitest";

const RELAY_ORIGIN = "http://relay.invalid";

interface Recorded {
    readonly posts: SharedSessionPost[];
    readonly controls: SharedSessionControl[];
    readonly states: SharedSessionState[];
    readonly terminations: string[];
}

function recorded(): Recorded {
    return { posts: [], controls: [], states: [], terminations: [] };
}

function callbacks(into: Recorded): SharedSessionCallbacks {
    return {
        persistEntry: async () => undefined,
        persistState: async (_transaction: StoreTransaction, state) => {
            into.states.push(state);
        },
        persistPost: async (_transaction: StoreTransaction, post) => {
            into.posts.push(post);
        },
        persistControl: async (_transaction: StoreTransaction, control) => {
            into.controls.push(control);
        },
        terminate: async (_transaction: StoreTransaction, termination) => {
            into.terminations.push(termination.reason);
        },
    };
}

const emptySource: SessionEntrySource = {
    readPage: async () => ({ entries: [], done: true }),
};

/** Resolve once `predicate` holds, or fail the test after `timeoutMs`. */
async function eventually(
    predicate: () => boolean,
    description: string,
    timeoutMs: number = 5_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!predicate()) {
        if (Date.now() > deadline) {
            throw new Error(`Timed out waiting for ${description}`);
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
}

describe("shared session ephemeral channel over the real relay", () => {
    const closeables: { close(): Promise<void> }[] = [];
    const destroyables: { destroy(): void }[] = [];

    afterEach(async () => {
        for (const destroyable of destroyables.splice(0)) {
            destroyable.destroy();
        }
        for (const closeable of closeables.splice(0).reverse()) {
            await closeable.close();
        }
    });

    it("streams keystrokes end to end, drops nothing durable, and closes on revoke", async () => {
        const service = new RelayService(new SqliteRelayStore(":memory:"), {
            streamKeepAliveMilliseconds: 200,
        });
        closeables.push(service);
        const handler = createRelayFetchHandler(service);
        const fetchRelay = async (
            input: RequestInfo | URL,
            init?: RequestInit,
        ): Promise<Response> => handler(new Request(input, init));

        const party = (
            identity: IdentityKeyPair,
        ): { client: MurmurClient; store: MemoryMurmurStore } => {
            const store = new MemoryMurmurStore();
            return {
                store,
                client: new MurmurClient({
                    identity,
                    store,
                    transports: [new HttpRelayTransport("relay", RELAY_ORIGIN, fetchRelay)],
                }),
            };
        };

        const ownerIdentity = generateIdentityKeyPair();
        const friendIdentity = generateIdentityKeyPair();
        const ownerSide = party(ownerIdentity);
        const friendSide = party(friendIdentity);
        const ownerRecorded = recorded();
        const friendRecorded = recorded();
        const invitations: SharedSessionInvitation[] = [];
        const bundle = createMlsKeyPackage(friendIdentity);

        const owner = await SharedSessionOwner.create("share_e2e_terminal", {
            identity: ownerIdentity,
            client: ownerSide.client,
            store: ownerSide.store,
            callbacks: callbacks(ownerRecorded),
            entrySource: emptySource,
            invitationDelivery: {
                deliver: async (invitation) => {
                    invitations.push(invitation);
                },
            },
        });
        destroyables.push(owner);
        await owner.invite({ identity: friendIdentity, keyPackage: bundle.keyPackage });
        const friend = await SharedSessionMember.join({
            identity: friendIdentity,
            client: friendSide.client,
            store: friendSide.store,
            callbacks: callbacks(friendRecorded),
            invitation: invitations[0]!.text,
            keyPackageBundle: bundle,
            expectedOwner: ownerIdentity,
        });
        destroyables.push(friend);

        const drain = async (
            client: MurmurClient,
            session: SharedSessionOwner | SharedSessionMember,
        ): Promise<void> => {
            const sync = await client.sync();
            if (sync.status !== "events") {
                throw new Error("unexpected reset");
            }
            for (const event of sync.events) {
                await session.handleEvent(event);
            }
        };
        await drain(ownerSide.client, owner);
        await drain(friendSide.client, friend);

        // Both sides open the low-latency channel over the same MLS group.
        const ownerChannel = owner.openEphemeralChannel();
        const friendChannel = friend.openEphemeralChannel();
        const ownerFrames: SharedSessionEphemeralFrame[] = [];
        const friendFrames: SharedSessionEphemeralFrame[] = [];
        ownerChannel.onReceived((frame) => ownerFrames.push(frame));
        friendChannel.onReceived((frame) => friendFrames.push(frame));

        // Let both SSE streams attach before the first frame is published.
        await eventually(() => service.ephemeralSubscriberCount >= 2, "two live relay streams");

        const started = Date.now();
        friendChannel.send(utf8Encode("ls -la\n"));
        await eventually(() => ownerFrames.length === 1, "the owner to receive one keystroke");
        const elapsed = Date.now() - started;
        // The whole point: this must not take the 25 second long poll.
        expect(elapsed).toBeLessThan(2_000);
        expect(utf8Decode(ownerFrames[0]!.bytes)).toBe("ls -la\n");
        expect(ownerFrames[0]!.authenticatedPeerId).toBe(identityId(friendIdentity));
        expect(ownerFrames[0]!.grantEpoch).toBe(1);

        ownerChannel.send(utf8Encode("total 0\n"));
        await eventually(() => friendFrames.length === 1, "the friend to receive terminal output");
        expect(utf8Decode(friendFrames[0]!.bytes)).toBe("total 0\n");

        // Many frames, in order, from one sender.
        for (let index = 0; index < 20; index += 1) {
            friendChannel.send(utf8Encode(`k${index.toString().padStart(2, "0")}`));
        }
        await eventually(() => ownerFrames.length === 21, "the burst to arrive");
        const burst = ownerFrames.slice(1).map((frame) => utf8Decode(frame.bytes));
        expect(burst).toEqual([...burst].sort());

        // Nothing ephemeral reached the durable topic or the callbacks.
        const headBefore = await ownerSide.client.sync();
        expect(headBefore.status).toBe("events");
        if (headBefore.status === "events") {
            expect(headBefore.events).toEqual([]);
        }
        expect(ownerRecorded.posts).toEqual([]);

        // Durable friend control still works, on its own typed frame.
        await friend.sendControl("cap-1", { kind: "request", capability: "terminal" }, 42);
        await drain(ownerSide.client, owner);
        expect(ownerRecorded.controls).toEqual([
            expect.objectContaining({
                authenticatedPeerId: identityId(friendIdentity),
                controlId: "cap-1",
                payload: { kind: "request", capability: "terminal" },
            }),
        ]);
        expect(ownerRecorded.posts).toEqual([]);

        // Revoking closes in-flight ephemeral traffic without a durable sync.
        const epochBefore = ownerChannel.epoch;
        await owner.revoke(friendIdentity);
        expect(ownerChannel.epoch).toBeGreaterThan(epochBefore);

        const beforeRevokeCount = ownerFrames.length;
        friendChannel.send(utf8Encode("should not arrive"));
        await new Promise<void>((resolve) => setTimeout(resolve, 300));
        expect(ownerFrames).toHaveLength(beforeRevokeCount);

        await drain(friendSide.client, friend);
        expect(friendRecorded.terminations).toEqual(["ended"]);
        expect(friendChannel.open).toBe(false);

        ownerChannel.close();
        friendChannel.close();
        await eventually(
            () => service.ephemeralSubscriberCount === 0,
            "every relay stream to be released",
        );
        destroyMlsKeyPackageBundle(bundle);
    }, 30_000);
});
