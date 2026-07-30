import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    ContactBook,
    decryptContactProfile,
    encryptProfileForContact,
    identityInboxTopic,
} from "../index.js";

describe("identity profiles", () => {
    it("exchanges an authenticated profile using only public identity keys", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();

        const envelope = encryptProfileForContact(alice, bob, {
            name: "Alice",
            metadata: { role: "agent" },
        });
        const opened = decryptContactProfile(bob, envelope);

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

    it("rejects oversized ciphertext before attempting decryption", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const envelope = encryptProfileForContact(alice, bob, { name: "Alice" });

        expect(() =>
            decryptContactProfile(bob, {
                ...envelope,
                ciphertext: "A".repeat(2_000_000),
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
});
