import { describe, expect, it } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import { serializePublicIdentity } from "../../identity/index.js";
import { MemoryMurmurStore, type StoreTransaction } from "../../storage/index.js";
import { equalBytes, utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    acceptPrivateMessageFromContact,
    createPrivateMessage,
    decodeEncryptedPrivateMessage,
    decodePrivateMessage,
    decryptPrivateMessageFromContact,
    decryptFile,
    encodeEncryptedPrivateMessage,
    encodePrivateMessage,
    encryptFile,
    encryptPrivateMessageForContact,
    privateMessageListElementId,
    type OpenedPrivateMessage,
} from "../index.js";

describe("encrypted files", () => {
    it("encrypts relay blobs and authenticates their metadata", () => {
        const encrypted = encryptFile(utf8Encode("private"), {
            name: "note.txt",
            mediaType: "text/plain",
        });

        expect(encrypted.blob.bytes).not.toEqual(utf8Encode("private"));
        expect(utf8Decode(decryptFile(encrypted.descriptor, encrypted.blob))).toBe("private");
        expect(() =>
            decryptFile({ ...encrypted.descriptor, name: "changed.txt" }, encrypted.blob),
        ).toThrow();
    });

    it("rejects path-like file names", () => {
        expect(() => encryptFile(utf8Encode("private"), { name: "../secret" })).toThrow(
            "descriptor",
        );
        for (const name of [
            "file:stream",
            "C:secret",
            "CON",
            "CONIN$",
            "COM¹",
            "report.",
            "😀".repeat(64),
        ]) {
            expect(() => encryptFile(utf8Encode("private"), { name })).toThrow("descriptor");
        }
    });
});

describe("private message content", () => {
    it("round trips an encrypted file descriptor", () => {
        const file = encryptFile(utf8Encode("private"), { name: "note.txt" });
        const message = createPrivateMessage("hello", [file.descriptor], 42);

        expect(decodePrivateMessage(encodePrivateMessage(message))).toEqual(message);
    });

    it("rejects more than 64 attachments", () => {
        const file = encryptFile(new Uint8Array(), { name: "empty" });

        expect(() =>
            createPrivateMessage(
                "",
                Array.from({ length: 65 }, () => file.descriptor),
            ),
        ).toThrow("message");
    });

    it("rejects unknown attachment versions instead of coercing them to version 1", () => {
        const file = encryptFile(utf8Encode("private"), { name: "note.txt" });
        const encoded = utf8Decode(
            encodePrivateMessage(createPrivateMessage("hello", [file.descriptor], 42)),
        ).replace('"version":1,"blobId"', '"version":2,"blobId"');

        expect(() => decodePrivateMessage(utf8Encode(encoded))).toThrow("descriptor");
    });

    it("rejects attachment plaintext sizes above the supported file limit", () => {
        const file = encryptFile(utf8Encode("private"), { name: "note.txt" });
        const encoded = utf8Decode(
            encodePrivateMessage(createPrivateMessage("hello", [file.descriptor], 42)),
        ).replace('"plaintextBytes":7', `"plaintextBytes":${Number.MAX_SAFE_INTEGER}`);

        expect(() => decodePrivateMessage(utf8Encode(encoded))).toThrow("descriptor");
    });
});

describe("direct private messages", () => {
    it("derives stable author-scoped list element identifiers", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const message = createPrivateMessage("stable", [], 42);

        expect(privateMessageListElementId(alice, message)).toBe(
            privateMessageListElementId(alice, message),
        );
        expect(privateMessageListElementId(bob, message)).not.toBe(
            privateMessageListElementId(alice, message),
        );
    });

    it("binds ciphertext and signature to sender, recipient, and content", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const mallory = generateIdentityKeyPair();
        const message = createPrivateMessage("hello Bob", [], 42);
        const encrypted = encryptPrivateMessageForContact(alice, bob, message);
        const decoded = decodeEncryptedPrivateMessage(encodeEncryptedPrivateMessage(encrypted));
        const opened = decryptPrivateMessageFromContact(bob, decoded);

        expect(opened.message).toEqual(message);
        expect(equalBytes(opened.identity.signingKey, alice.signingKey)).toBe(true);
        expect(() => decryptPrivateMessageFromContact(mallory, decoded)).toThrow("not addressed");
        expect(() =>
            decryptPrivateMessageFromContact(bob, {
                ...decoded,
                sender: serializePublicIdentity(mallory),
            }),
        ).toThrow();
    });

    it("rejects unknown envelope fields before decryption", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const encrypted = encryptPrivateMessageForContact(
            alice,
            bob,
            createPrivateMessage("hello"),
        );
        const encoded = utf8Encode(
            JSON.stringify({
                ...encrypted,
                unexpected: true,
            }),
        );

        expect(() => decodeEncryptedPrivateMessage(encoded)).toThrow("encrypted private message");
    });

    it("rejects inherited fields and accessors at the object boundary", () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const encrypted = encryptPrivateMessageForContact(
            alice,
            bob,
            createPrivateMessage("hello"),
        );
        const inherited = Object.create(encrypted) as typeof encrypted;
        const accessor = { ...encrypted };
        Object.defineProperty(accessor, "ciphertext", {
            enumerable: true,
            get: () => encrypted.ciphertext,
        });

        expect(() => encodeEncryptedPrivateMessage(inherited)).toThrow(
            "Invalid encrypted private message",
        );
        expect(() => encodeEncryptedPrivateMessage(accessor)).toThrow(
            "Invalid encrypted private message",
        );
    });

    it("durably rejects inner-message replay collisions", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const message = createPrivateMessage("first", [], 42);
        const first = encryptPrivateMessageForContact(alice, bob, message);
        const replay = encryptPrivateMessageForContact(alice, bob, message);
        const collision = encryptPrivateMessageForContact(alice, bob, {
            ...message,
            text: "different signed content",
        });
        let persisted = 0;
        const persist = async (
            transaction: StoreTransaction,
            opened: OpenedPrivateMessage,
        ): Promise<void> => {
            persisted += 1;
            await transaction.set(`inbox/${opened.message.id}`, utf8Encode(opened.message.text));
        };

        await expect(
            acceptPrivateMessageFromContact(store, bob, first, persist),
        ).resolves.toMatchObject({
            message,
            status: "opened",
        });
        await expect(
            acceptPrivateMessageFromContact(store, bob, replay, persist),
        ).resolves.toMatchObject({
            message,
            status: "duplicate",
        });
        await expect(
            acceptPrivateMessageFromContact(store, bob, collision, persist),
        ).rejects.toThrow("ID collision");
        expect(persisted).toBe(1);
        expect(utf8Decode((await store.get(`inbox/${message.id}`)) ?? new Uint8Array())).toBe(
            "first",
        );

        const restarted = new MemoryMurmurStore();
        const records = await store.list("");
        for (const [key, value] of records) {
            await restarted.set(key, value);
        }
        await expect(
            acceptPrivateMessageFromContact(restarted, bob, replay, persist),
        ).resolves.toMatchObject({
            status: "duplicate",
        });
        expect(persisted).toBe(1);
    });

    it("rolls back application state and replay state together", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const file = encryptFile(utf8Encode("attachment"), { name: "note.txt" });
        const encrypted = encryptPrivateMessageForContact(
            alice,
            bob,
            createPrivateMessage("survives retry", [file.descriptor], 42),
        );
        let rejectedKey: Uint8Array | undefined;
        let rejectedNonce: Uint8Array | undefined;

        await expect(
            acceptPrivateMessageFromContact(store, bob, encrypted, async (transaction, opened) => {
                rejectedKey = opened.message.attachments[0]?.key;
                rejectedNonce = opened.message.attachments[0]?.nonce;
                await transaction.set(
                    `inbox/${opened.message.id}`,
                    utf8Encode(opened.message.text),
                );
                throw new Error("simulated crash");
            }),
        ).rejects.toThrow("simulated crash");
        expect(await store.list("")).toHaveLength(0);
        expect(rejectedKey?.every((byte) => byte === 0)).toBe(true);
        expect(rejectedNonce?.every((byte) => byte === 0)).toBe(true);

        await expect(
            acceptPrivateMessageFromContact(store, bob, encrypted, async (transaction, opened) => {
                await transaction.set(
                    `inbox/${opened.message.id}`,
                    utf8Encode(opened.message.text),
                );
            }),
        ).resolves.toMatchObject({
            status: "opened",
        });
    });

    it("commits duplicate decisions and relay cursors in the same transaction", async () => {
        const alice = generateIdentityKeyPair();
        const bob = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        const encrypted = encryptPrivateMessageForContact(
            alice,
            bob,
            createPrivateMessage("atomic cursor", [], 42),
        );

        await acceptPrivateMessageFromContact(
            store,
            bob,
            encrypted,
            async (transaction, opened) => {
                await transaction.set("application/message", utf8Encode(opened.message.text));
            },
            async (transaction) => {
                await transaction.set("relay/cursor", utf8Encode("1"));
            },
        );
        await expect(
            acceptPrivateMessageFromContact(
                store,
                bob,
                encrypted,
                async () => {
                    throw new Error("duplicate must not be reapplied");
                },
                async (transaction) => {
                    await transaction.set("relay/cursor", utf8Encode("2"));
                },
            ),
        ).resolves.toMatchObject({ status: "duplicate" });

        expect(utf8Decode((await store.get("relay/cursor")) ?? new Uint8Array())).toBe("2");
        expect(utf8Decode((await store.get("application/message")) ?? new Uint8Array())).toBe(
            "atomic cursor",
        );
    });
});
