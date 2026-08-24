import { describe, expect, it } from "vitest";
import { destroyIdentity, generateIdentityKeyPair } from "../../../crypto/index.js";
import {
    createMlsKeyPackage,
    destroyMlsKeyPackageBundle,
    encodeMlsKeyPackage,
} from "../../../mls/index.js";
import { MemoryMurmurStore } from "../../../storage/index.js";
import { zeroBytes } from "../../../utils/index.js";
import { encodeContactPacket } from "../contactCodec.js";
import { ContactEngine } from "../contactEngine.js";
import {
    contactIdentityKey,
    contactSessionKey,
    encodeContactRecord,
    type ContactRecord,
} from "../contactRecords.js";

const NOW = 1_700_000_000_000;

describe("contact profile processing", () => {
    it("durably ignores duplicate and reordered updates and retains one lifecycle event", async () => {
        const local = generateIdentityKeyPair();
        const remote = generateIdentityKeyPair();
        const oneTime = createMlsKeyPackage(remote, Math.floor(NOW / 1_000));
        const fallback = createMlsKeyPackage(remote, Math.floor(NOW / 1_000));
        const store = new MemoryMurmurStore();
        const sessionId = new Uint8Array(32).fill(7);
        const record: ContactRecord = {
            version: 2,
            identity: remote.publicKey,
            sessionId,
            localProfile: { name: "Local" },
            profile: { name: "Remote" },
            localProfileRevision: 0,
            remoteProfileRevision: 0,
            status: "active",
            confirmedAt: NOW,
            localAdmissionGeneration: 1,
            remoteAdmission: {
                generation: 1,
                oneTimeKeyPackages: [encodeMlsKeyPackage(oneTime.keyPackage)],
                lastResortKeyPackage: encodeMlsKeyPackage(fallback.keyPackage),
            },
            refillNeeded: false,
        };
        const encoded = encodeContactRecord(record);
        try {
            await store.set(contactIdentityKey(remote.publicKey), encoded);
            await store.set(contactSessionKey(sessionId), encoded);
            const engine = new ContactEngine(store, local.publicKey, () => NOW);
            const newest = encodeContactPacket({
                version: 2,
                type: "profile_update",
                revision: 2,
                profile: { name: "Newest", state: "online" },
            });
            const older = encodeContactPacket({
                version: 2,
                type: "profile_update",
                revision: 1,
                profile: { name: "Older" },
            });
            try {
                await engine.process({
                    id: "profile-newest",
                    sessionId,
                    sender: remote.publicKey,
                    bytes: newest,
                });
                await engine.process({
                    id: "profile-older",
                    sessionId,
                    sender: remote.publicKey,
                    bytes: older,
                });
                await engine.process({
                    id: "profile-newest",
                    sessionId,
                    sender: remote.publicKey,
                    bytes: newest,
                });
                await engine.process({
                    id: "profile-newest-duplicate",
                    sessionId,
                    sender: remote.publicKey,
                    bytes: newest,
                });

                expect(await engine.contact(remote.publicKey)).toMatchObject({
                    profile: { name: "Newest", state: "online" },
                });
                const prepared = await engine.prepareEvents();
                expect(prepared.updated).toHaveLength(1);
                expect(prepared.updated[0]).toMatchObject({
                    id: "profile-newest",
                    contact: { profile: { name: "Newest", state: "online" } },
                });

                const reopened = new ContactEngine(store, local.publicKey, () => NOW);
                expect((await reopened.prepareEvents()).updated).toEqual(prepared.updated);
                await store.transaction((transaction) =>
                    reopened.deletePreparedEvents(transaction, prepared),
                );
                expect((await reopened.prepareEvents()).updated).toEqual([]);
                await reopened.process({
                    id: "profile-newest",
                    sessionId,
                    sender: remote.publicKey,
                    bytes: newest,
                });
                expect((await reopened.prepareEvents()).updated).toEqual([]);

                await expect(
                    reopened.process({
                        id: "profile-conflict",
                        sessionId,
                        sender: remote.publicKey,
                        bytes: encodeContactPacket({
                            version: 2,
                            type: "profile_update",
                            revision: 2,
                            profile: { name: "Conflict" },
                        }),
                    }),
                ).rejects.toThrow("Conflicting contact profile revision");
            } finally {
                zeroBytes(newest);
                zeroBytes(older);
            }
        } finally {
            zeroBytes(encoded);
            destroyMlsKeyPackageBundle(oneTime);
            destroyMlsKeyPackageBundle(fallback);
            destroyIdentity(local);
            destroyIdentity(remote);
        }
    });
});
