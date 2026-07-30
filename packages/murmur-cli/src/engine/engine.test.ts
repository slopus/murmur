/**
 * Tests for the messaging engine.
 *
 * Uses mock server to test full chat flow without network.
 */

import { createId } from "@paralleldrive/cuid2";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MurmurEngine } from "./engine.js";
import { MockServer, createMockApi } from "./mockServer.js";

describe("MurmurEngine", () => {
    let tempDir: string;
    let engine: MurmurEngine;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), "murmur-engine-test-"));
    });

    afterEach(() => {
        if (engine) {
            engine.close();
        }
        rmSync(tempDir, { recursive: true, force: true });
    });

    describe("Account creation", () => {
        it("should report no account initially", () => {
            engine = new MurmurEngine(join(tempDir, "test.db"));
            expect(engine.hasAccount()).toBe(false);
            expect(engine.getAccount()).toBeNull();
        });

        // Note: Full account creation test would require mocking the API
        // or using the mock server. We test the database layer separately.
    });

    describe("Contacts", () => {
        it("should start with empty contacts", () => {
            engine = new MurmurEngine(join(tempDir, "test.db"));
            expect(engine.getContacts()).toEqual([]);
        });

        it("should surface backend login failure when adding a contact", async () => {
            engine = new MurmurEngine(join(tempDir, "test.db"));
            (engine as any).agent = {};
            (engine as any).authError =
                "Authentication rate limit exceeded. Max 1000 attempts per minute.";
            (engine as any).api = {
                getTokens: () => null,
            };

            const profileSecretKey = Buffer.alloc(32).toString("base64url");

            await expect(engine.addContactByProfileSecret(profileSecretKey)).rejects.toThrow(
                "Backend login failed: Authentication rate limit exceeded. Max 1000 attempts per minute.",
            );
        });
    });

    describe("Conversations", () => {
        it("should return empty conversations initially", () => {
            engine = new MurmurEngine(join(tempDir, "test.db"));
            expect(engine.getConversations()).toEqual([]);
        });
    });
});

describe("MockServer integration with Engine concepts", () => {
    let server: MockServer;

    beforeEach(() => {
        server = new MockServer();
    });

    it("should simulate full chat flow", async () => {
        // Alice registers
        const aliceResult = server.register(
            "alice-identity",
            "alice-profile-key",
            "alice-sig",
            "alice-profile",
        );
        expect(aliceResult.tokens.accessToken).toBeDefined();

        // Bob registers
        const bobResult = server.register(
            "bob-identity",
            "bob-profile-key",
            "bob-sig",
            "bob-profile",
        );
        expect(bobResult.tokens.accessToken).toBeDefined();

        // Alice sends message to Bob
        const msgResult = server.sendMessage(
            aliceResult.tokens.accessToken,
            "msg-1",
            "bob-identity",
            "encrypted-hello",
            "alice-signature",
        );
        expect(msgResult.id).toBe("msg-1");

        // Bob checks inbox
        const inbox = server.getInbox(bobResult.tokens.accessToken);
        expect(inbox.messages).toHaveLength(1);
        expect(inbox.messages[0].senderId).toBe("alice-identity");
        expect(inbox.messages[0].blob).toBe("encrypted-hello");

        // Bob acknowledges
        const ackResult = server.acknowledgeMessages(bobResult.tokens.accessToken, ["msg-1"]);
        expect(ackResult.acknowledged).toBe(1);

        // Inbox now empty
        const inbox2 = server.getInbox(bobResult.tokens.accessToken);
        expect(inbox2.messages).toHaveLength(0);
    });

    it("should simulate bidirectional conversation", async () => {
        const aliceApi = createMockApi(server);
        const bobApi = createMockApi(server);

        await aliceApi.register("alice", new Uint8Array(32), "ppk", "sig", "ep");
        await bobApi.register("bob", new Uint8Array(32), "ppk", "sig", "ep");

        // Alice -> Bob
        await aliceApi.sendMessage("bob", "hello-bob", createId());

        // Bob -> Alice
        await bobApi.sendMessage("alice", "hi-alice", createId());

        // Check Alice's inbox
        const aliceInbox = await aliceApi.getInbox();
        expect(aliceInbox.messages).toHaveLength(1);
        expect(aliceInbox.messages[0].blob).toBe("hi-alice");

        // Check Bob's inbox
        const bobInbox = await bobApi.getInbox();
        expect(bobInbox.messages).toHaveLength(1);
        expect(bobInbox.messages[0].blob).toBe("hello-bob");
    });

    it("should handle multiple messages in conversation", async () => {
        const aliceApi = createMockApi(server);
        const bobApi = createMockApi(server);

        await aliceApi.register("alice", new Uint8Array(32), "ppk", "sig", "ep");
        await bobApi.register("bob", new Uint8Array(32), "ppk", "sig", "ep");

        // Send 10 messages
        for (let i = 0; i < 10; i++) {
            await aliceApi.sendMessage("bob", `message-${i}`, createId());
        }

        // Bob receives all 10
        const inbox = await bobApi.getInbox();
        expect(inbox.messages).toHaveLength(10);

        // Messages are in order
        for (let i = 0; i < 10; i++) {
            expect(inbox.messages[i].blob).toBe(`message-${i}`);
        }
    });

    it("should persist profile updates", async () => {
        const api = createMockApi(server);

        await api.register("alice", new Uint8Array(32), "old-ppk", "old-sig", "old-profile");

        // Get initial profile
        const profile1 = await api.getMyProfile();
        expect(profile1.profilePublicKey).toBe("old-ppk");

        // Update profile
        await api.updateProfile("new-ppk", "new-sig", "new-profile");

        // Get updated profile
        const profile2 = await api.getMyProfile();
        expect(profile2.profilePublicKey).toBe("new-ppk");
        expect(profile2.encryptedProfile).toBe("new-profile");
    });

    it("should allow fetching other user profiles", async () => {
        const aliceApi = createMockApi(server);
        const bobApi = createMockApi(server);

        await aliceApi.register("alice", new Uint8Array(32), "alice-ppk", "sig", "alice-profile");
        await bobApi.register("bob", new Uint8Array(32), "bob-ppk", "sig", "bob-profile");

        // Alice fetches Bob's profile
        const bobProfile = await aliceApi.getProfile("bob-ppk");
        expect(bobProfile.id).toBe("bob");
        expect(bobProfile.profilePublicKey).toBe("bob-ppk");
        expect(bobProfile.encryptedProfile).toBe("bob-profile");
    });

    it("should handle token refresh", async () => {
        const api = createMockApi(server);

        const result = await api.register("alice", new Uint8Array(32), "ppk", "sig", "ep");
        const originalToken = api.getTokens()!.accessToken;

        // Refresh token
        const newToken = await api.refresh();
        expect(newToken).not.toBe(originalToken);

        // New token works
        const profile = await api.getMyProfile();
        expect(profile.id).toBe("alice");
    });
});
