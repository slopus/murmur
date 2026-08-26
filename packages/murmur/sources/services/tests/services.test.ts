import { describe, expect, it } from "vitest";
import {
    createMurmurServiceSessionDescriptor,
    validateMurmurServiceRegistration,
    validateServiceId,
    type MurmurService,
} from "../index.js";

const service: MurmurService = {
    onNewSession: () => true,
    onUpdate: () => undefined,
};

describe("Murmur services", () => {
    it("strictly validates stable registrations", () => {
        expect(() => validateServiceId("chat.v1")).not.toThrow();
        expect(() =>
            validateMurmurServiceRegistration({ id: "messaging.v1", service }),
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
        expect(() =>
            validateMurmurServiceRegistration({
                id: "chat.v1",
                service: {
                    ...service,
                    onSessionDeleted: true,
                } as unknown as MurmurService,
            }),
        ).toThrow("Invalid Murmur service registration");
    });

    it("passes defensive session byte copies across the callback boundary", () => {
        const original = {
            id: new Uint8Array(32).fill(1),
            descriptor: new Uint8Array([2, 3]),
            members: [new Uint8Array(32).fill(4), new Uint8Array(32).fill(5)],
            owner: new Uint8Array(32).fill(4),
            admins: [new Uint8Array(32).fill(4)],
            policies: {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
                sendPolicy: "everyone" as const,
            },
        };
        const descriptor = createMurmurServiceSessionDescriptor(original);
        descriptor.id[0] = 99;
        descriptor.descriptor[0] = 99;
        descriptor.members[0]![0] = 99;
        descriptor.owner[0] = 99;
        descriptor.admins[0]![0] = 99;

        expect(original.id[0]).toBe(1);
        expect(original.descriptor[0]).toBe(2);
        expect(original.members[0]![0]).toBe(4);
        expect(original.owner[0]).toBe(4);
        expect(original.admins[0]![0]).toBe(4);
        expect(Object.isFrozen(descriptor)).toBe(true);
        expect(Object.isFrozen(descriptor.members)).toBe(true);
    });
});
