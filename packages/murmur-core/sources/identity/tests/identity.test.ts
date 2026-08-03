import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair, hashBytes } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    ContactBook,
    FriendBook,
    decryptContactProfile,
    encryptProfileForContact,
    identityInboxTopic,
    pairwiseTopic,
} from "../index.js";
import { canonicalJsonBytes, encodeBase64Url, utf8Encode } from "../../utils/index.js";

describe("identity profiles", () => {
    it("derives symmetric pairwise topics unavailable from public tokens", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const aliceBob = pairwiseTopic(alice, bob);
        const publicKeys = [
            encodeBase64Url(alice.encryptionKey),
            encodeBase64Url(bob.encryptionKey),
        ].sort();
        const publicOnlyGuess = `pairwise:${encodeBase64Url(
            hashBytes(
                canonicalJsonBytes({
                    context: "murmur/pairwise-topic/x25519-sha256/v1",
                    publicKeys,
                }),
            ),
        )}`;

        expect(pairwiseTopic(bob, alice)).toBe(aliceBob);
        expect(pairwiseTopic(alice, eve)).not.toBe(aliceBob);
        expect(pairwiseTopic(eve, bob)).not.toBe(aliceBob);
        expect(publicOnlyGuess).not.toBe(aliceBob);
        expect(aliceBob).toMatch(/^pairwise:[A-Za-z0-9_-]{43}$/);
    });

    it("exchanges an authenticated profile using only public identity keys", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();

        const envelope = encryptProfileForContact(alice, bob, {
            name: "Alice",
            metadata: { role: "agent" },
        });
        const opened = decryptContactProfile(bob, envelope);

        expect("sender" in envelope).toBe(false);
        expect(JSON.stringify(envelope)).not.toContain(encodeBase64Url(alice.signingKey));
        expect(opened.identity.signingKey).toEqual(alice.signingKey);
        expect(opened.profile).toEqual({ name: "Alice", metadata: { role: "agent" } });
        expect(identityInboxTopic(bob)).toMatch(/^identity:/);
    });

    it("cannot be opened by another identity", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const eve = generateIdentityKeyPair();
        const envelope = encryptProfileForContact(alice, bob, { name: "Alice" });

        expect(() => decryptContactProfile(eve, envelope)).toThrow();
    });

    it("seals sender identity and authenticated private contact data together", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const privateData = utf8Encode("private KeyPackage bytes");
        const envelope = encryptProfileForContact(alice, bob, { name: "Alice" }, privateData);
        const wire = JSON.stringify(envelope);
        const opened = decryptContactProfile(bob, envelope);

        expect(wire).not.toContain(encodeBase64Url(alice.signingKey));
        expect(wire).not.toContain(encodeBase64Url(privateData));
        expect(opened.privateData).toEqual(privateData);
    });

    it("rejects oversized ciphertext before attempting decryption", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const envelope = encryptProfileForContact(alice, bob, { name: "Alice" });

        expect(() =>
            decryptContactProfile(bob, {
                ...envelope,
                ciphertext: "A".repeat(3_000_000),
            }),
        ).toThrow("too large");
    });

    it("round trips metadata magic keys as plain data", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const metadata = JSON.parse('{"__proto__":"safe"}') as Record<string, string>;
        const envelope = encryptProfileForContact(alice, bob, {
            name: "Alice",
            metadata,
        });

        const opened = decryptContactProfile(bob, envelope);

        expect(opened.profile.metadata?.["__proto__"]).toBe("safe");
        expect(Object.prototype.hasOwnProperty.call(opened.profile.metadata, "__proto__")).toBe(
            true,
        );
    });

    it("decrypts a large profile accepted by the sender", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const avatar = new Uint8Array(700_000);
        avatar.fill(7);

        const envelope = encryptProfileForContact(alice, bob, {
            name: "Alice",
            avatar,
        });
        const opened = decryptContactProfile(bob, envelope);

        expect(opened.profile.avatar).toEqual(avatar);
    });

    it("persists authenticated contacts in an owner namespace", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const sharedStore = new MemoryMurmurStore();
        const aliceContacts = new ContactBook(alice, sharedStore);
        const bobContacts = new ContactBook(bob, sharedStore);
        const opened = decryptContactProfile(
            alice,
            encryptProfileForContact(bob, alice, { name: "Bob" }),
        );

        await aliceContacts.save(opened, 10);
        await aliceContacts.save({ ...opened, profile: { name: "Bobby" } }, 20);

        expect((await aliceContacts.get(bob))?.profile.name).toBe("Bobby");
        expect((await aliceContacts.get(bob))?.addedAt).toBe(10);
        expect(await bobContacts.list()).toHaveLength(0);
        await expect(aliceContacts.save(opened, 5)).rejects.toThrow("backwards");

        await expect(
            aliceContacts.save({
                ...opened,
                identity: { ...opened.identity, encryptionKey: new Uint8Array() },
            }),
        ).rejects.toThrow("32 bytes");
        await expect(aliceContacts.get({ signingKey: new Uint8Array() })).rejects.toThrow(
            "32 bytes",
        );
    });

    it("retains removed friends and reactivates them without changing addedAt", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const friends = new FriendBook(alice, store);
        const opened = {
            identity: bob,
            profile: { name: "Bob" },
        };

        const added = await friends.save(opened, 10);
        const removed = await friends.remove(bob, 20);

        expect(added).toMatchObject({
            addedAt: 10,
            updatedAt: 10,
            status: "active",
            statusUpdatedAt: 10,
        });
        expect(removed).toMatchObject({
            addedAt: 10,
            updatedAt: 10,
            status: "removed",
            statusUpdatedAt: 20,
        });
        expect(await friends.get(bob)).toBeUndefined();
        expect(await friends.list()).toEqual([]);
        expect((await friends.get(bob, { includeRemoved: true }))?.profile.name).toBe("Bob");

        const reactivated = await friends.save({ ...opened, profile: { name: "Bobby" } }, 30);
        expect(reactivated).toMatchObject({
            addedAt: 10,
            updatedAt: 30,
            status: "active",
            statusUpdatedAt: 30,
        });
        expect((await friends.list())[0]?.profile.name).toBe("Bobby");
        await expect(friends.remove(bob, 29)).rejects.toThrow("backwards");
    });

    it("strictly rejects corrupt durable friend lifecycle values", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const friends = new FriendBook(alice, store);
        await friends.save({ identity: bob, profile: { name: "Bob" } }, 10);
        const key = [...(await store.list("identity/")).keys()][0];
        if (key === undefined) {
            throw new Error("Expected one durable friend");
        }
        const value = (await store.get(key)) ?? new Uint8Array();
        const corrupt = JSON.parse(new TextDecoder().decode(value)) as Record<string, unknown>;
        corrupt.unexpected = true;
        await store.set(key, new TextEncoder().encode(JSON.stringify(corrupt)));

        await expect(friends.get(bob, { includeRemoved: true })).rejects.toThrow(
            "persisted friend",
        );
    });
});
