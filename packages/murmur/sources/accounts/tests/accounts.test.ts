import { describe, expect, test } from "vitest";
import { generateIdentityKeyPair } from "../../crypto/index.js";
import {
    decodeDeviceRosterMutation,
    encodeDeviceRosterMutation,
    parseDeviceRoster,
    serializeDeviceRoster,
    type MurmurDeviceRoster,
} from "../index.js";

describe("relay-owned device roster codecs", () => {
    test("round-trips current roster entries and admissions canonically", () => {
        const account = generateIdentityKeyPair();
        const device = generateIdentityKeyPair();
        const roster: MurmurDeviceRoster = {
            version: 1,
            accountKey: account.publicKey,
            revision: 3,
            devices: [
                {
                    deviceKey: device.publicKey,
                    resetGeneration: 2,
                    lastAccessedAt: 1_700_000_000_000,
                    encryptedMetadata: new Uint8Array([9, 10]),
                },
            ],
            admissions: [{ deviceKey: device.publicKey, keyPackage: new Uint8Array([1, 2, 3]) }],
        };
        expect(parseDeviceRoster(serializeDeviceRoster(roster))).toEqual(roster);
    });

    test("round-trips register and remove mutation plaintext", () => {
        const device = generateIdentityKeyPair();
        const register = {
            version: 1 as const,
            type: "register" as const,
            deviceKey: device.publicKey,
            resetGeneration: 4,
            keyPackage: new Uint8Array([7, 8]),
            encryptedMetadata: new Uint8Array([9, 10]),
        };
        expect(decodeDeviceRosterMutation(encodeDeviceRosterMutation(register))).toEqual(register);
        const updateMetadata = {
            version: 1 as const,
            type: "update_metadata" as const,
            deviceKey: device.publicKey,
            resetGeneration: 4,
            encryptedMetadata: new Uint8Array([11, 12]),
        };
        expect(decodeDeviceRosterMutation(encodeDeviceRosterMutation(updateMetadata))).toEqual(
            updateMetadata,
        );
        const remove = {
            version: 1 as const,
            type: "remove" as const,
            deviceKey: device.publicKey,
            resetGeneration: 4,
        };
        expect(decodeDeviceRosterMutation(encodeDeviceRosterMutation(remove))).toEqual(remove);
    });

    test("rejects unknown fields and unsorted devices", () => {
        const first = generateIdentityKeyPair();
        const second = generateIdentityKeyPair();
        const account = generateIdentityKeyPair();
        const ordered = [first.publicKey, second.publicKey].sort((left, right) =>
            Buffer.compare(right, left),
        );
        expect(() =>
            serializeDeviceRoster({
                version: 1,
                accountKey: account.publicKey,
                revision: 1,
                devices: ordered.map((deviceKey) => ({
                    deviceKey,
                    resetGeneration: 0,
                    lastAccessedAt: 1_700_000_000_000,
                    encryptedMetadata: new Uint8Array(),
                })),
                admissions: ordered.map((deviceKey) => ({
                    deviceKey,
                    keyPackage: new Uint8Array([1]),
                })),
            }),
        ).toThrow("sorted and unique");
    });
});
