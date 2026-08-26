import {
    SqlitePrivateGroupStateStore,
    createPrivateGroupStateFetchHandler,
    createPrivateGroupStateServiceFromSecret,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { destroyIdentity, generateIdentityKeyPair } from "../../crypto/index.js";
import type { MurmurSession } from "../../sessions/index.js";
import { equalBytes, utf8Encode } from "../../utils/index.js";
import {
    createPrivateGroupSessionState,
    createReadyPrivateGroupState,
    decodePrivateGroupSessionState,
    destroyPrivateGroupSessionState,
    encodePrivateGroupSessionState,
    updatePrivateGroupSessionTrustedTip,
    type PrivateGroupSessionState,
    type PrivateGroupStateTransport,
    type PrivateGroupTrustedTip,
    type StoredPrivateGroupStateRecord,
} from "../index.js";

const NOW = 1_800_000_000_000;
const VERSION_ONE = "018f0000-0000-7000-8000-000000000001";
const VERSION_TWO = "018f0000-0000-7000-8000-000000000002";

function bytes(seed: number): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, index) => (seed + index * 29) & 0xff);
}

function activeSession(
    id: Uint8Array,
    owner: Uint8Array,
    members: readonly Uint8Array[],
): MurmurSession {
    return {
        id,
        status: "active",
        descriptor: utf8Encode("private group ready session"),
        members,
        owner,
        admins: [owner],
        policies: { adminsAssignAdmins: false, anyoneCanAddMembers: false },
        bufferedEvents: 0,
    };
}

function sessionState(sessionId: Uint8Array, masterSecret: Uint8Array): PrivateGroupSessionState {
    return {
        version: 1,
        sessionId: sessionId.slice(),
        masterSecret: masterSecret.slice(),
    };
}

function tip(canonicalVersion: string, revision: number, hashSeed: number): PrivateGroupTrustedTip {
    return { canonicalVersion, revision, revisionHash: bytes(hashSeed) };
}

class RecordingTransport implements PrivateGroupStateTransport {
    readonly credentialIssuerPublicParameters: Uint8Array;
    readonly #delegate: PrivateGroupStateTransport;
    created: StoredPrivateGroupStateRecord | undefined;
    replaced: StoredPrivateGroupStateRecord | undefined;
    staleRead: StoredPrivateGroupStateRecord | undefined;

    constructor(delegate: PrivateGroupStateTransport) {
        this.#delegate = delegate;
        this.credentialIssuerPublicParameters = delegate.credentialIssuerPublicParameters;
    }

    credentialIssuanceContext(authenticationContext: Uint8Array): Uint8Array {
        return this.#delegate.credentialIssuanceContext(authenticationContext);
    }

    async issueCredential(
        options: Parameters<PrivateGroupStateTransport["issueCredential"]>[0],
    ): Promise<Uint8Array> {
        return await this.#delegate.issueCredential(options);
    }

    async createPresentationChallenge(
        options: Parameters<PrivateGroupStateTransport["createPresentationChallenge"]>[0],
    ): ReturnType<PrivateGroupStateTransport["createPresentationChallenge"]> {
        return await this.#delegate.createPresentationChallenge(options);
    }

    async authenticatePresentation(
        options: Parameters<PrivateGroupStateTransport["authenticatePresentation"]>[0],
    ): ReturnType<PrivateGroupStateTransport["authenticatePresentation"]> {
        return await this.#delegate.authenticatePresentation(options);
    }

    async createRecord(
        options: Parameters<PrivateGroupStateTransport["createRecord"]>[0],
    ): Promise<StoredPrivateGroupStateRecord> {
        const stored = await this.#delegate.createRecord(options);
        this.created = stored;
        return stored;
    }

    async readRecord(
        options: Parameters<PrivateGroupStateTransport["readRecord"]>[0],
    ): Promise<StoredPrivateGroupStateRecord> {
        return this.staleRead ?? (await this.#delegate.readRecord(options));
    }

    async replaceRecord(
        options: Parameters<PrivateGroupStateTransport["replaceRecord"]>[0],
    ): Promise<StoredPrivateGroupStateRecord> {
        const stored = await this.#delegate.replaceRecord(options);
        this.replaced = stored;
        return stored;
    }
}

describe("private-group session state", () => {
    test("strictly round-trips canonical member-only state and zeroes secrets", () => {
        const created = createPrivateGroupSessionState(bytes(1));
        const withTip = updatePrivateGroupSessionTrustedTip(created, tip(VERSION_ONE, 1, 2));
        const encoded = encodePrivateGroupSessionState(withTip);
        const decoded = decodePrivateGroupSessionState(encoded);
        expect(decoded).toEqual(withTip);
        expect(decoded.masterSecret).not.toBe(withTip.masterSecret);
        expect(decoded.trustedTip?.revisionHash).not.toBe(withTip.trustedTip?.revisionHash);

        const nonCanonical = new Uint8Array(encoded.length + 1);
        nonCanonical.set(encoded);
        nonCanonical[encoded.length] = 0x0a;
        expect(() => decodePrivateGroupSessionState(nonCanonical)).toThrow(
            "Invalid private-group session state",
        );

        destroyPrivateGroupSessionState(decoded);
        destroyPrivateGroupSessionState(decoded);
        expect(decoded.masterSecret).toEqual(new Uint8Array(32));
        expect(decoded.trustedTip?.revisionHash).toEqual(new Uint8Array(32));
        destroyPrivateGroupSessionState(withTip);
        destroyPrivateGroupSessionState(created);
    });

    test("rejects rollback, fork, and gap tips while accepting a direct successor", () => {
        const state = sessionState(bytes(3), bytes(4));
        const first = updatePrivateGroupSessionTrustedTip(state, tip(VERSION_ONE, 1, 5));
        expect(() =>
            updatePrivateGroupSessionTrustedTip(
                first,
                tip("018f0000-0000-7000-8000-000000000000", 1, 5),
            ),
        ).toThrow("rollback");
        expect(() => updatePrivateGroupSessionTrustedTip(first, tip(VERSION_ONE, 1, 6))).toThrow(
            "fork",
        );
        expect(() => updatePrivateGroupSessionTrustedTip(first, tip(VERSION_TWO, 3, 7))).toThrow(
            "gap",
        );
        const second = updatePrivateGroupSessionTrustedTip(first, tip(VERSION_TWO, 2, 8));
        expect(second.trustedTip).toEqual(tip(VERSION_TWO, 2, 8));
        expect(equalBytes(second.masterSecret, state.masterSecret)).toBe(true);

        destroyPrivateGroupSessionState(second);
        destroyPrivateGroupSessionState(first);
        destroyPrivateGroupSessionState(state);
    });
});

describe("ready private-group state handle", () => {
    test("uses the signed HTTP connection and derives the live roster on every operation", async () => {
        const identity = generateIdentityKeyPair();
        const sessionId = bytes(20);
        const masterSecret = bytes(21);
        let liveSession = activeSession(sessionId, identity.publicKey, [identity.publicKey]);
        let durableState = sessionState(sessionId, masterSecret);
        const service = createPrivateGroupStateServiceFromSecret({
            store: new SqlitePrivateGroupStateStore(":memory:"),
            secret: bytes(22),
            now: () => NOW,
        });
        const handler = createPrivateGroupStateFetchHandler(service);
        const handle = await createReadyPrivateGroupState({
            identity,
            state: durableState,
            connection: {
                relay: "https://relay.example",
                fetch: async (input, init): Promise<Response> =>
                    await handler(new Request(input, init)),
            },
            session: () => liveSession,
            persistTrustedTip: (next): void => {
                const updated = updatePrivateGroupSessionTrustedTip(durableState, next);
                destroyPrivateGroupSessionState(durableState);
                durableState = updated;
            },
            now: () => NOW,
        });
        try {
            const created = await handle.create(utf8Encode("alpha"));
            expect(created.revision).toBe(1);
            await expect(handle.create(utf8Encode("duplicate"))).rejects.toThrow(
                "already initialized locally",
            );
            const replaced = await handle.mutate(utf8Encode("beta"));
            expect(replaced.revision).toBe(2);
            expect(new TextDecoder().decode((await handle.read()).attributes)).toBe("beta");

            const member = bytes(23);
            liveSession = activeSession(sessionId, identity.publicKey, [
                identity.publicKey,
                member,
            ]);
            const rosterReplacement = await handle.mutate(utf8Encode("gamma"));
            expect(rosterReplacement.revision).toBe(3);
            expect(durableState.trustedTip?.revision).toBe(3);

            liveSession = { ...liveSession, status: "pending" };
            await expect(handle.read()).rejects.toThrow("active authenticated MLS session");
        } finally {
            handle.close();
            handle.close();
            await expect(handle.read()).rejects.toThrow("handle is closed");
            service.close();
            destroyPrivateGroupSessionState(durableState);
            destroyIdentity(identity);
            masterSecret.fill(0);
        }
    });

    test("joins through a custom transport and rejects a stale record after restart", async () => {
        const ownerIdentity = generateIdentityKeyPair();
        const memberIdentity = generateIdentityKeyPair();
        const sessionId = bytes(30);
        const masterSecret = bytes(31);
        const session = activeSession(sessionId, ownerIdentity.publicKey, [
            ownerIdentity.publicKey,
            memberIdentity.publicKey,
        ]);
        const service = createPrivateGroupStateServiceFromSecret({
            store: new SqlitePrivateGroupStateStore(":memory:"),
            secret: bytes(32),
            now: () => NOW,
        });
        const transport = new RecordingTransport(service);
        let ownerState = sessionState(sessionId, masterSecret);
        let memberState = sessionState(sessionId, masterSecret);
        const owner = await createReadyPrivateGroupState({
            identity: ownerIdentity,
            state: ownerState,
            connection: { transport },
            session: () => session,
            persistTrustedTip: (next): void => {
                const updated = updatePrivateGroupSessionTrustedTip(ownerState, next);
                destroyPrivateGroupSessionState(ownerState);
                ownerState = updated;
            },
            now: () => NOW,
        });
        try {
            await owner.create(utf8Encode("alpha"));
            await owner.mutate(utf8Encode("beta"));
            const first = transport.created;
            expect(first?.record.revision).toBe(1);
            expect(transport.replaced?.record.revision).toBe(2);

            const member = await createReadyPrivateGroupState({
                identity: memberIdentity,
                state: memberState,
                connection: { transport },
                session: () => session,
                persistTrustedTip: (next): void => {
                    const updated = updatePrivateGroupSessionTrustedTip(memberState, next);
                    destroyPrivateGroupSessionState(memberState);
                    memberState = updated;
                },
                now: () => NOW,
            });
            expect(new TextDecoder().decode((await member.join()).attributes)).toBe("beta");
            expect(memberState.trustedTip?.revision).toBe(2);
            member.close();

            if (first === undefined) throw new Error("Missing captured first revision");
            transport.staleRead = first;
            let persistenceCalls = 0;
            const reopened = await createReadyPrivateGroupState({
                identity: memberIdentity,
                state: memberState,
                connection: { transport },
                session: () => session,
                persistTrustedTip: (): void => {
                    persistenceCalls += 1;
                },
                now: () => NOW,
            });
            await expect(reopened.read()).rejects.toThrow("rollback detected");
            expect(persistenceCalls).toBe(0);
            reopened.close();
            reopened.close();
            await expect(reopened.read()).rejects.toThrow("handle is closed");
        } finally {
            owner.close();
            service.close();
            destroyPrivateGroupSessionState(ownerState);
            destroyPrivateGroupSessionState(memberState);
            destroyIdentity(ownerIdentity);
            destroyIdentity(memberIdentity);
            masterSecret.fill(0);
        }
    });

    test("fails closed when the accepted tip cannot be persisted", async () => {
        const identity = generateIdentityKeyPair();
        const sessionId = bytes(40);
        const state = sessionState(sessionId, bytes(41));
        const session = activeSession(sessionId, identity.publicKey, [identity.publicKey]);
        const service = createPrivateGroupStateServiceFromSecret({
            store: new SqlitePrivateGroupStateStore(":memory:"),
            secret: bytes(42),
            now: () => NOW,
        });
        const handle = await createReadyPrivateGroupState({
            identity,
            state,
            connection: { transport: service },
            session: () => session,
            persistTrustedTip: (): never => {
                throw new Error("durable store unavailable");
            },
            now: () => NOW,
        });
        try {
            await expect(handle.create(utf8Encode("alpha"))).rejects.toThrow(
                "durable store unavailable",
            );
            await expect(handle.read()).rejects.toThrow("handle is closed");
            expect(() => handle.close()).not.toThrow();
        } finally {
            handle.close();
            service.close();
            destroyPrivateGroupSessionState(state);
            destroyIdentity(identity);
        }
    });
});
