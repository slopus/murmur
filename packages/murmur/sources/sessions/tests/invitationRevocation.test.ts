import { RelayService, SqliteRelayStore, createRelayFetchHandler } from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import type { DeliveryFetch } from "../../delivery/index.js";
import { DISCOVERY_INVITATION_TTL_MILLISECONDS } from "../../identity/discovery/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { utf8Encode } from "../../utils/index.js";
import { MurmurClient } from "../index.js";

const NOW = 1_700_000_000_000;

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "invitation-revocation-tests",
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

async function client(relay: RelayService, store = new MemoryMurmurStore()): Promise<MurmurClient> {
    return MurmurClient.open({
        relay: "https://relay.test",
        fetch: relayFetch(relay),
        store,
        now: () => NOW,
    });
}

describe("invitation revocation", () => {
    test("revokes one or every owner-created invitation without granting digest holders authority", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const owner = await client(relay);
        const attacker = await client(relay);
        const recipient = await client(relay);
        try {
            const first = await owner.createInvitation();
            const second = await owner.createInvitation();
            await expect(attacker.revokeInvitation(first)).rejects.toMatchObject({
                status: 401,
                code: "invitation_revocation_unauthorized",
            });
            await expect(recipient.resolveInvitation(first)).resolves.toMatchObject({
                identityKey: owner.identity,
            });

            await owner.revokeInvitation(first);
            await owner.revokeInvitation(first);
            await expect(recipient.resolveInvitation(first)).rejects.toMatchObject({
                status: 404,
                code: "invitation_not_found",
            });
            await expect(recipient.resolveInvitation(second)).resolves.toMatchObject({
                identityKey: owner.identity,
            });

            await owner.revokeInvitations();
            await owner.revokeInvitations();
            await expect(recipient.resolveInvitation(second)).rejects.toMatchObject({
                status: 404,
                code: "invitation_not_found",
            });
        } finally {
            owner.close();
            attacker.close();
            recipient.close();
            await relay.close();
        }
    });

    test("persists revocation authority and retries relay failure after destroying local use keys", async () => {
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => NOW);
        const baseFetch = relayFetch(relay);
        let failRevocation = true;
        const unreliableFetch: DeliveryFetch = async (input, init): Promise<Response> => {
            const request = new Request(input, init);
            if (failRevocation && new URL(request.url).pathname === "/v1/invitations/revoke") {
                failRevocation = false;
                throw new Error("injected relay outage");
            }
            return baseFetch(request);
        };
        const ownerStore = new MemoryMurmurStore();
        let owner = await MurmurClient.open({
            relay: "https://relay.test",
            fetch: unreliableFetch,
            store: ownerStore,
            now: () => NOW,
        });
        const recipient = await client(relay);
        try {
            const digest = await owner.createInvitation();
            await expect(owner.revokeInvitation(digest)).rejects.toThrow("injected relay outage");
            expect(await ownerStore.scan("murmur/key-packages/", { limit: 10 })).toHaveLength(0);
            await expect(recipient.resolveInvitation(digest)).resolves.toMatchObject({
                identityKey: owner.identity,
            });

            const identity = owner.identity;
            owner.close();
            owner = await MurmurClient.open({
                relay: "https://relay.test",
                fetch: baseFetch,
                store: ownerStore,
                now: () => NOW,
            });
            expect(owner.identity).toEqual(identity);
            await owner.revokeInvitation(digest);
            await expect(recipient.resolveInvitation(digest)).rejects.toMatchObject({
                status: 404,
                code: "invitation_not_found",
            });
        } finally {
            owner.close();
            recipient.close();
            await relay.close();
        }
    });

    test("keeps an established session valid when its invitation is revoked or expires", async () => {
        let now = NOW;
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const fetch = relayFetch(relay);
        const owner = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        const recipient = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: new MemoryMurmurStore(),
            now: () => now,
        });
        try {
            const redeemed = await owner.createInvitation();
            const session = await recipient.createSession({
                descriptor: utf8Encode("redeemed invitation"),
                members: [await recipient.resolveInvitation(redeemed)],
            });
            await recipient.synchronize({ waitMilliseconds: 0 });
            await owner.synchronize({ waitMilliseconds: 0 });
            expect(await owner.session(session.id)).toMatchObject({ status: "pending" });
            await owner.revokeInvitation(redeemed);
            await owner.revokeInvitation(redeemed);
            expect(await owner.session(session.id)).toMatchObject({ status: "pending" });

            const expired = await owner.createInvitation();
            now += DISCOVERY_INVITATION_TTL_MILLISECONDS;
            await owner.revokeInvitation(expired);
            await owner.revokeInvitation(expired);
            await expect(recipient.resolveInvitation(expired)).rejects.toMatchObject({
                status: 404,
                code: "invitation_not_found",
            });
        } finally {
            owner.close();
            recipient.close();
            await relay.close();
        }
    });
});
