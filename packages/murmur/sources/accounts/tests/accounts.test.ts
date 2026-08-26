import { describe, expect, test } from "vitest";
import { destroyIdentity, generateIdentityKeyPair } from "../../crypto/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import { equalBytes, zeroBytes } from "../../utils/index.js";
import {
    addDeviceToRoster,
    authorizeDeviceProvisioning,
    completeDeviceProvisioning,
    createDeviceLinkMaterial,
    createInitialDeviceRoster,
    decodeDeviceCredential,
    deviceRosterHash,
    encodeDeviceCredential,
    isActiveDevice,
    accountConvergenceJobs,
    observeDeviceRoster,
    parseDeviceRoster,
    revokeDeviceFromRoster,
    resetDeviceInRoster,
    selectDeviceRosterChild,
    serializeDeviceRoster,
    verifyDeviceRoster,
} from "../index.js";

const NOW = 1_700_000_000_000;

describe("account device rosters", () => {
    test("signs ordered direct children and deterministically resolves forks", () => {
        const account = generateIdentityKeyPair();
        const first = generateIdentityKeyPair();
        const second = generateIdentityKeyPair();
        const third = generateIdentityKeyPair();
        try {
            const initial = createInitialDeviceRoster(account, first, NOW, new Uint8Array(16));
            const left = addDeviceToRoster(
                initial,
                account,
                first,
                second.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(1),
            );
            const right = addDeviceToRoster(
                initial,
                account,
                first,
                third.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(2),
            );
            expect(verifyDeviceRoster(initial)).toBe(true);
            expect(parseDeviceRoster(serializeDeviceRoster(left))).toEqual(left);
            const firstSelection = selectDeviceRosterChild(initial, [left, right]);
            const secondSelection = selectDeviceRosterChild(initial, [right, left]);
            expect(firstSelection).toBeDefined();
            expect(deviceRosterHash(firstSelection!)).toEqual(deviceRosterHash(secondSelection!));
            expect(selectDeviceRosterChild(left, [right])).toBeUndefined();
        } finally {
            destroyIdentity(account);
            destroyIdentity(first);
            destroyIdentity(second);
            destroyIdentity(third);
        }
    });

    test("binds MLS credentials and revocation to the stable account", () => {
        const account = generateIdentityKeyPair();
        const first = generateIdentityKeyPair();
        const second = generateIdentityKeyPair();
        try {
            const initial = createInitialDeviceRoster(account, first, NOW, new Uint8Array(16));
            const added = addDeviceToRoster(
                initial,
                account,
                first,
                second.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(1),
            );
            const credential = decodeDeviceCredential(
                encodeDeviceCredential(added, second.publicKey),
            );
            expect(credential.accountKey).toEqual(account.publicKey);
            expect(credential.deviceKey).toEqual(second.publicKey);
            const revoked = revokeDeviceFromRoster(
                added,
                account,
                first,
                second.publicKey,
                NOW + 2,
                new Uint8Array(16).fill(2),
            );
            expect(isActiveDevice(revoked, second.publicKey)).toBe(false);
            expect(() => encodeDeviceCredential(revoked, second.publicKey)).toThrow(
                "Device is not active",
            );
        } finally {
            destroyIdentity(account);
            destroyIdentity(first);
            destroyIdentity(second);
        }
    });

    test("signs a monotonic reset and queues remove-then-add convergence for peers", async () => {
        const account = generateIdentityKeyPair();
        const device = generateIdentityKeyPair();
        const observer = generateIdentityKeyPair();
        const store = new MemoryMurmurStore();
        try {
            const initial = createInitialDeviceRoster(account, device, NOW, new Uint8Array(16));
            const reset = resetDeviceInRoster(
                initial,
                account,
                device,
                device.publicKey,
                NOW + 1,
                new Uint8Array(16).fill(1),
            );
            expect(reset.devices[0]!.resetGeneration).toBe(1);
            expect(parseDeviceRoster(serializeDeviceRoster(reset))).toEqual(reset);
            await store.transaction(async (transaction) => {
                await observeDeviceRoster(
                    transaction,
                    observer.publicKey,
                    "initial",
                    account.publicKey,
                    device.publicKey,
                    serializeDeviceRoster(initial),
                );
                await observeDeviceRoster(
                    transaction,
                    observer.publicKey,
                    "reset",
                    account.publicKey,
                    device.publicKey,
                    serializeDeviceRoster(reset),
                    { device: device.publicKey, keyPackage: new Uint8Array([1]) },
                );
            });
            const jobs = await accountConvergenceJobs(store);
            expect(jobs.map((job) => job.change)).toEqual(["reset_add"]);
        } finally {
            destroyIdentity(account);
            destroyIdentity(device);
            destroyIdentity(observer);
        }
    });
});

describe("device provisioning", () => {
    test("proves possession and transfers signature custody over the bound transcript", () => {
        const account = generateIdentityKeyPair();
        const first = generateIdentityKeyPair();
        const second = generateIdentityKeyPair();
        const material = createDeviceLinkMaterial(second, new Uint8Array([1, 2, 3]), NOW);
        try {
            const initial = createInitialDeviceRoster(account, first, NOW, new Uint8Array(16));
            const authorized = authorizeDeviceProvisioning({
                request: material.request,
                account,
                authorDevice: first,
                roster: initial,
                now: NOW + 1,
            });
            const result = completeDeviceProvisioning(material, authorized.envelope, NOW + 2);
            try {
                expect(result.account.publicKey).toEqual(account.publicKey);
                expect(isActiveDevice(result.roster, second.publicKey)).toBe(true);
                expect(equalBytes(result.account.secretKey, account.secretKey)).toBe(true);
            } finally {
                destroyIdentity(result.account);
            }
            expect(() =>
                completeDeviceProvisioning(
                    {
                        ...material,
                        request: { ...material.request, requestId: new Uint8Array(32).fill(7) },
                    },
                    authorized.envelope,
                    NOW + 2,
                ),
            ).toThrow();
            expect(() =>
                completeDeviceProvisioning(
                    material,
                    authorized.envelope,
                    material.request.expiresAt,
                ),
            ).toThrow("Invalid or expired");
        } finally {
            zeroBytes(material.ephemeralSecretKey);
            destroyIdentity(account);
            destroyIdentity(first);
            destroyIdentity(second);
        }
    });
});
