import { describe, expect, it } from "vitest";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    createMurmurServiceSessionDescriptor,
    createMurmurServiceStorage,
    validateMurmurServiceRegistration,
    validateServiceId,
    type MurmurService,
    type MurmurServiceJsonValue,
} from "../index.js";

const service: MurmurService = {
    onNewSession: () => true,
    onUpdate: () => undefined,
};

describe("Murmur services", () => {
    it("strictly validates stable registrations", () => {
        expect(() => validateServiceId("chat.v1")).not.toThrow();
        expect(() =>
            validateMurmurServiceRegistration({ id: "contacts.v1", service }),
        ).not.toThrow();

        for (const id of ["", "Chat", "chat/v1", "chat..v1", ".chat", "chat_", "a".repeat(65)]) {
            expect(() => validateServiceId(id)).toThrow("Invalid Murmur service ID");
        }
        expect(() =>
            validateMurmurServiceRegistration({
                id: "chat.v1",
                service: { ...service, onUpdate: undefined } as unknown as MurmurService,
            }),
        ).toThrow("Invalid Murmur service registration");
    });

    it("passes defensive session byte copies across the callback boundary", () => {
        const original = {
            id: new Uint8Array(32).fill(1),
            descriptor: new Uint8Array([2, 3]),
            members: [new Uint8Array(32).fill(4), new Uint8Array(32).fill(5)],
            committer: new Uint8Array(32).fill(4),
        };
        const descriptor = createMurmurServiceSessionDescriptor(original);
        descriptor.id[0] = 99;
        descriptor.descriptor[0] = 99;
        descriptor.members[0]![0] = 99;
        descriptor.committer[0] = 99;

        expect(original.id[0]).toBe(1);
        expect(original.descriptor[0]).toBe(2);
        expect(original.members[0]![0]).toBe(4);
        expect(original.committer[0]).toBe(4);
        expect(Object.isFrozen(descriptor)).toBe(true);
        expect(Object.isFrozen(descriptor.members)).toBe(true);
    });

    it("isolates canonical JSON by encoded service namespace", async () => {
        const store = new MemoryMurmurStore();
        const chat = createMurmurServiceStorage(store, "chat.v1");
        const presence = createMurmurServiceStorage(store, "presence.v1");
        const input = { nested: { count: 1 }, tags: ["a", "b"] };

        await chat.set("rooms/alpha", input);
        input.nested.count = 9;
        input.tags.push("c");
        await presence.set("rooms/alpha", { online: true });

        const first = await chat.get("rooms/alpha");
        expect(first).toEqual({ nested: { count: 1 }, tags: ["a", "b"] });
        expect(Object.isFrozen(first)).toBe(true);
        expect(Object.isFrozen((first as { readonly nested: object }).nested)).toBe(true);
        expect(await presence.get("rooms/alpha")).toEqual({ online: true });

        const all = await store.list("murmur/services/v1/");
        expect(all.size).toBe(2);
        expect([...all.keys()].every((key) => !key.includes("chat.v1"))).toBe(true);
    });

    it("validates keys, values, scans, and stored canonical JSON", async () => {
        const store = new MemoryMurmurStore();
        const storage = createMurmurServiceStorage(store, "chat.v1");
        for (const key of ["", "/root", "root/", "root//child", "../escape", "root\\child"]) {
            await expect(storage.set(key, null)).rejects.toThrow(
                "Invalid Murmur service storage key",
            );
        }
        await expect(
            storage.set("bad", { value: Number.NaN } as unknown as MurmurServiceJsonValue),
        ).rejects.toThrow("Invalid Murmur service JSON value");
        await storage.set("rooms/a", { value: 1 });
        await storage.set("rooms/b", { value: 2 });
        await storage.set("users/a", { value: 3 });

        const page = await storage.scan("rooms/", { after: "rooms/a", limit: 1 });
        expect([...page]).toEqual([["rooms/b", { value: 2 }]]);
        await expect(storage.scan("", { limit: 257 })).rejects.toThrow(
            "Invalid Murmur service storage scan",
        );
        await expect(storage.scan("rooms/", { after: "users/a", limit: 1 })).rejects.toThrow(
            "Invalid Murmur service storage scan",
        );

        const [storedKey] = [...(await store.list("murmur/services/v1/")).keys()];
        await store.set(storedKey!, new TextEncoder().encode('{ "value": 1 }'));
        await expect(storage.get("rooms/a")).rejects.toThrow(
            "Stored Murmur service JSON must be canonical",
        );
    });
});
