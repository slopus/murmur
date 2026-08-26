import { PGlite } from "@electric-sql/pglite";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, test } from "vitest";
import {
    eventId,
    identity,
    recipients,
    secret,
    signedDelivery,
} from "../../protocol/tests/helpers.js";
import type { DirectoryPrekeyUpload, SignedDelivery } from "../../protocol/index.js";
import type { DirectoryTicketClaims } from "../../directory/index.js";
import { RelayService } from "../../relay/index.js";
import { encodeBase64Url } from "../../utils/base64Url.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import {
    parseRelayStoreBackend,
    PGliteDatabase,
    PostgresRelayStore,
    SqliteRelayStore,
    type RelayStore,
} from "../index.js";

const NOW = 10_000;
const LIMITS = {
    maximumRecipients: 1_024,
    maximumItems: 10,
    maximumBytes: 1_000_000,
    maximumSenderItems: 10,
    maximumSenderBytes: 1_000_000,
    maximumSenderReferences: 1_000,
    maximumAdmissionReferences: 1_000,
    maximumGlobalItems: 100,
    maximumGlobalBytes: 10_000_000,
    maximumGlobalReferences: 1_000,
};
const PAGE = { maximumEncodedBytes: 2_000_000 };
const ADMISSION_PRINCIPAL = new Uint8Array(32).fill(250);

async function stores(): Promise<readonly RelayStore[]> {
    return [
        new SqliteRelayStore(":memory:"),
        await PostgresRelayStore.create(new PGliteDatabase(new PGlite())),
    ];
}

describe("identity queue store conformance", () => {
    test("persists and arbitrates authenticated session state with relay-derived fanout", async () => {
        const ownerAccountSecret = secret(101);
        const ownerAccount = identity(ownerAccountSecret);
        const ownerDeviceOneSecret = secret(102);
        const ownerDeviceOne = identity(ownerDeviceOneSecret);
        const ownerDeviceTwoSecret = secret(103);
        const ownerDeviceTwo = identity(ownerDeviceTwoSecret);
        const memberAccountSecret = secret(104);
        const memberAccount = identity(memberAccountSecret);
        const memberDeviceOneSecret = secret(105);
        const memberDeviceOne = identity(memberDeviceOneSecret);
        const memberDeviceTwoSecret = secret(106);
        const memberDeviceTwo = identity(memberDeviceTwoSecret);
        const outsiderAccountSecret = secret(107);
        const outsiderAccount = identity(outsiderAccountSecret);
        const outsiderDeviceSecret = secret(108);
        const outsiderDevice = identity(outsiderDeviceSecret);
        const sessionId = identity(secret(109));
        const memberAccounts = recipients(ownerAccount, memberAccount);
        const initialDevices = recipients(
            ownerDeviceOne,
            ownerDeviceTwo,
            memberDeviceOne,
            memberDeviceTwo,
        );
        const roles = {
            owner: ownerAccount,
            admins: [] as readonly Uint8Array[],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
            sendPolicy: "everyone" as const,
        };
        const register = async (
            relay: RelayService,
            accountSecret: Uint8Array,
            currentDevices: readonly Uint8Array[],
            deviceKey: Uint8Array,
            id: number,
        ): Promise<void> => {
            const ciphertext = canonicalJson({
                version: 1,
                type: "register",
                deviceKey: encodeBase64Url(deviceKey),
                resetGeneration: 0,
                keyPackage: encodeBase64Url(new Uint8Array([id])),
            });
            await relay.mutateDeviceRoster(
                signedDelivery(accountSecret, recipients(...currentDevices), {
                    id,
                    ciphertext,
                }),
                "session-conformance",
            );
        };

        for (const store of await stores()) {
            const relay = new RelayService(store, {}, undefined, () => NOW);
            try {
                await register(relay, ownerAccountSecret, [ownerDeviceOne], ownerDeviceOne, 101);
                await register(
                    relay,
                    ownerAccountSecret,
                    [ownerDeviceOne, ownerDeviceTwo],
                    ownerDeviceTwo,
                    102,
                );
                await register(relay, memberAccountSecret, [memberDeviceOne], memberDeviceOne, 103);
                await register(
                    relay,
                    memberAccountSecret,
                    [memberDeviceOne, memberDeviceTwo],
                    memberDeviceTwo,
                    104,
                );
                await register(relay, outsiderAccountSecret, [outsiderDevice], outsiderDevice, 105);

                const creation = signedDelivery(ownerDeviceOneSecret, [], {
                    id: 106,
                    senderAccount: ownerAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "create",
                        epoch: 0n,
                        members: memberAccounts,
                        roles,
                        coveredDevices: initialDevices,
                    },
                });
                expect(creation.recipients).toEqual([]);
                await expect(relay.publish(creation, "session-conformance")).resolves.toMatchObject(
                    { duplicate: false },
                );
                await expect(store.readSessionState(sessionId)).resolves.toMatchObject({
                    epoch: 1n,
                    ownerAccount,
                    members: memberAccounts,
                    sendPolicy: "everyone",
                });
                for (const device of initialDevices) {
                    const page = await store.readQueue(device, null, 100, NOW, PAGE);
                    expect(
                        page.deliveries.some(({ delivery }) => delivery.id === creation.id),
                    ).toBe(true);
                }

                const outsiderSend = signedDelivery(outsiderDeviceSecret, [], {
                    id: 107,
                    senderAccount: outsiderAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "message",
                        epoch: 1n,
                        content: "application",
                        coveredDevices: initialDevices,
                    },
                });
                await expect(
                    relay.publish(outsiderSend, "session-conformance"),
                ).rejects.toMatchObject({
                    status: 403,
                    body: { error: "session_unauthorized" },
                });

                const adminsOnly = signedDelivery(ownerDeviceOneSecret, [], {
                    id: 108,
                    senderAccount: ownerAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "commit",
                        epoch: 1n,
                        members: memberAccounts,
                        roles: { ...roles, sendPolicy: "admins" },
                        changes: [],
                        coveredDevices: initialDevices,
                    },
                });
                await relay.publish(adminsOnly, "session-conformance");
                const rejectedMemberSend = signedDelivery(memberDeviceOneSecret, [], {
                    id: 109,
                    senderAccount: memberAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "message",
                        epoch: 2n,
                        content: "application",
                        coveredDevices: initialDevices,
                    },
                });
                await expect(
                    relay.publish(rejectedMemberSend, "session-conformance"),
                ).rejects.toMatchObject({
                    status: 403,
                    body: { error: "session_unauthorized" },
                });

                const unauthorizedSummary = signedDelivery(memberDeviceOneSecret, [], {
                    id: 110,
                    senderAccount: memberAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "commit",
                        epoch: 2n,
                        members: recipients(...memberAccounts, outsiderAccount),
                        roles: { ...roles, sendPolicy: "admins" },
                        changes: [
                            {
                                type: "add",
                                accountKey: outsiderAccount,
                                deviceKey: outsiderDevice,
                            },
                        ],
                        coveredDevices: recipients(...initialDevices, outsiderDevice),
                    },
                });
                await expect(
                    relay.publish(unauthorizedSummary, "session-conformance"),
                ).rejects.toMatchObject({
                    status: 403,
                    body: { error: "session_unauthorized" },
                });

                const winner = signedDelivery(ownerDeviceOneSecret, [], {
                    id: 111,
                    senderAccount: ownerAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "commit",
                        epoch: 2n,
                        members: memberAccounts,
                        roles: {
                            ...roles,
                            sendPolicy: "admins",
                            anyoneCanAddMembers: true,
                        },
                        changes: [],
                        coveredDevices: initialDevices,
                    },
                });
                const loser = signedDelivery(ownerDeviceTwoSecret, [], {
                    id: 112,
                    senderAccount: ownerAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "commit",
                        epoch: 2n,
                        members: memberAccounts,
                        roles: {
                            ...roles,
                            sendPolicy: "admins",
                            adminsAssignAdmins: true,
                        },
                        changes: [],
                        coveredDevices: initialDevices,
                    },
                });
                await relay.publish(winner, "session-conformance");
                await expect(relay.publish(loser, "session-conformance")).rejects.toMatchObject({
                    status: 409,
                    body: { error: "stale_session_epoch", epoch: "3" },
                });
                await expect(store.readSessionState(sessionId)).resolves.toMatchObject({
                    epoch: 3n,
                    anyoneCanAddMembers: true,
                    adminsAssignAdmins: false,
                });

                const ownerDeviceThreeSecret = secret(110);
                const ownerDeviceThree = identity(ownerDeviceThreeSecret);
                await register(
                    relay,
                    ownerAccountSecret,
                    [ownerDeviceOne, ownerDeviceTwo, ownerDeviceThree],
                    ownerDeviceThree,
                    113,
                );
                const staleCoverage = signedDelivery(ownerDeviceOneSecret, [], {
                    id: 114,
                    senderAccount: ownerAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "message",
                        epoch: 3n,
                        content: "application",
                        coveredDevices: initialDevices,
                    },
                });
                await expect(
                    relay.publish(staleCoverage, "session-conformance"),
                ).rejects.toMatchObject({
                    status: 409,
                    body: { error: "stale_epoch_coverage" },
                });

                const convergedDevices = recipients(...initialDevices, ownerDeviceThree);
                const deviceCommit = signedDelivery(ownerDeviceOneSecret, [], {
                    id: 115,
                    senderAccount: ownerAccount,
                    ownerAccount,
                    sessionId,
                    sessionControl: {
                        version: 1,
                        type: "commit",
                        epoch: 3n,
                        members: memberAccounts,
                        roles: {
                            ...roles,
                            sendPolicy: "admins",
                            anyoneCanAddMembers: true,
                        },
                        changes: [
                            {
                                type: "add",
                                accountKey: ownerAccount,
                                deviceKey: ownerDeviceThree,
                            },
                        ],
                        coveredDevices: convergedDevices,
                    },
                });
                await relay.publish(deviceCommit, "session-conformance");
                await expect(store.readSessionState(sessionId)).resolves.toMatchObject({
                    epoch: 4n,
                });

                const direct = signedDelivery(outsiderDeviceSecret, recipients(ownerDeviceOne), {
                    id: 116,
                    senderAccount: outsiderAccount,
                });
                await expect(relay.publish(direct, "session-conformance")).resolves.toMatchObject({
                    duplicate: false,
                });
                await store.deleteSessionDeliveries(ownerAccount, sessionId, "delete-state", NOW);
                await expect(store.readSessionState(sessionId)).resolves.toBeUndefined();
                const ownerQueue = await store.readQueue(ownerDeviceOne, null, 100, NOW, PAGE);
                expect(
                    ownerQueue.deliveries.some(({ delivery }) => delivery.id === direct.id),
                ).toBe(true);
                expect(
                    ownerQueue.deliveries.some(({ delivery }) => delivery.sessionControl !== null),
                ).toBe(false);
            } finally {
                await relay.close();
            }
        }
    });

    test("rotates, replenishes, and atomically claims one directory prekey per device", async () => {
        const accountSecret = secret(80);
        const account = identity(accountSecret);
        const firstSecret = secret(81);
        const first = identity(firstSecret);
        const secondSecret = secret(82);
        const second = identity(secondSecret);
        const thirdSecret = secret(83);
        const third = identity(thirdSecret);
        const mutationBytes = (deviceKey: Uint8Array): Uint8Array =>
            canonicalJson({
                version: 1,
                type: "register",
                deviceKey: encodeBase64Url(deviceKey),
                resetGeneration: 0,
                keyPackage: encodeBase64Url(new Uint8Array([9])),
            });
        const spent = (
            deviceSecret: Uint8Array,
            deviceKey: Uint8Array,
            reference: Uint8Array,
            id: number,
        ): SignedDelivery =>
            signedDelivery(deviceSecret, recipients(deviceKey), {
                id,
                ciphertext: canonicalJson({
                    version: 1,
                    type: "directory_prekey_spent",
                    reference: encodeBase64Url(reference),
                }),
                expiresAt: NOW + 1_000,
            });
        const upload = (
            deviceKey: Uint8Array,
            deviceSecret: Uint8Array,
            resetGeneration: number,
            mode: "replenish" | "rotate",
            values: readonly { readonly value: number; readonly id: number }[],
            lastResortValue: number,
        ): DirectoryPrekeyUpload => ({
            version: 1,
            type: "directory_prekey_upload",
            mode,
            deviceKey,
            resetGeneration,
            oneTimePrekeys: values
                .map(({ value, id }) => {
                    const reference = new Uint8Array(32).fill(value);
                    return {
                        reference,
                        keyPackage: new Uint8Array([value]),
                        expiresAt: NOW + 1_000,
                        spentNotification: spent(deviceSecret, deviceKey, reference, id),
                    };
                })
                .sort((left, right) => left.reference[0]! - right.reference[0]!),
            lastResort: {
                reference: new Uint8Array(32).fill(lastResortValue),
                keyPackage: new Uint8Array([lastResortValue]),
                expiresAt: NOW + 1_000,
            },
        });
        const ticket: DirectoryTicketClaims = {
            issuer: "test",
            ticketId: new Uint8Array(32).fill(83),
            expiresAt: NOW + 1_000,
            claimBudget: 10,
        };
        for (const store of await stores()) {
            try {
                await store.mutateDeviceRoster(
                    signedDelivery(accountSecret, recipients(first), {
                        id: 80,
                        ciphertext: mutationBytes(first),
                    }),
                    {
                        version: 1,
                        type: "register",
                        deviceKey: first,
                        resetGeneration: 0,
                        keyPackage: new Uint8Array([9]),
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await store.mutateDeviceRoster(
                    signedDelivery(accountSecret, recipients(first, second), {
                        id: 81,
                        ciphertext: mutationBytes(second),
                    }),
                    {
                        version: 1,
                        type: "register",
                        deviceKey: second,
                        resetGeneration: 0,
                        keyPackage: new Uint8Array([9]),
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const firstRotation = upload(
                    first,
                    firstSecret,
                    0,
                    "rotate",
                    [
                        { value: 1, id: 84 },
                        { value: 2, id: 85 },
                    ],
                    10,
                );
                const secondRotation = upload(
                    second,
                    secondSecret,
                    0,
                    "rotate",
                    [{ value: 3, id: 86 }],
                    11,
                );
                const firstOuter = signedDelivery(accountSecret, [], { id: 87 });
                const secondOuter = signedDelivery(accountSecret, [], { id: 88 });
                await store.uploadDirectoryPrekeys(firstOuter, firstRotation, NOW);
                await store.uploadDirectoryPrekeys(secondOuter, secondRotation, NOW);
                await store.mutateDeviceRoster(
                    signedDelivery(accountSecret, recipients(first, second, third), {
                        id: 93,
                        ciphertext: mutationBytes(third),
                    }),
                    {
                        version: 1,
                        type: "register",
                        deviceKey: third,
                        resetGeneration: 0,
                        keyPackage: new Uint8Array([9]),
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );

                await expect(
                    store.claimDirectory(
                        account,
                        ticket,
                        NOW,
                        { ...LIMITS, maximumGlobalItems: 0 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 503, body: { error: "relay_full" } });
                const firstClaim = await store.claimDirectory(
                    account,
                    ticket,
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                expect(
                    firstClaim.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "one_time", keyPackage: new Uint8Array([1]) });
                expect(
                    firstClaim.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(second),
                    ),
                ).toMatchObject({ source: "one_time", keyPackage: new Uint8Array([3]) });
                expect(
                    firstClaim.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(third),
                    ),
                ).toMatchObject({ source: "last_resort", keyPackage: new Uint8Array([9]) });
                const secondClaim = await store.claimDirectory(
                    account,
                    ticket,
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                expect(
                    secondClaim.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "one_time", keyPackage: new Uint8Array([2]) });
                expect(
                    secondClaim.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(second),
                    ),
                ).toMatchObject({ source: "last_resort", keyPackage: new Uint8Array([11]) });
                const fallback = await store.claimDirectory(
                    account,
                    ticket,
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                expect(
                    fallback.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "last_resort", keyPackage: new Uint8Array([10]) });
                expect(
                    fallback.devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(second),
                    ),
                ).toMatchObject({ source: "last_resort", keyPackage: new Uint8Array([11]) });

                const changedFallback = upload(first, firstSecret, 0, "replenish", [], 10);
                await expect(
                    store.uploadDirectoryPrekeys(
                        signedDelivery(accountSecret, [], { id: 97 }),
                        {
                            ...changedFallback,
                            lastResort: {
                                ...changedFallback.lastResort,
                                keyPackage: new Uint8Array([99]),
                            },
                        },
                        NOW,
                    ),
                ).rejects.toMatchObject({
                    status: 409,
                    body: { error: "last_resort_stale" },
                });

                const replenishment = upload(
                    first,
                    firstSecret,
                    0,
                    "replenish",
                    [{ value: 4, id: 89 }],
                    10,
                );
                await store.uploadDirectoryPrekeys(
                    signedDelivery(accountSecret, [], { id: 90 }),
                    replenishment,
                    NOW,
                );
                await expect(
                    store.uploadDirectoryPrekeys(
                        signedDelivery(accountSecret, [], { id: 94 }),
                        replenishment,
                        NOW,
                    ),
                ).resolves.toBeUndefined();
                expect(
                    (
                        await store.claimDirectory(
                            account,
                            ticket,
                            NOW,
                            LIMITS,
                            ADMISSION_PRINCIPAL,
                        )
                    ).devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "one_time", keyPackage: new Uint8Array([4]) });
                const rotated = upload(first, firstSecret, 0, "rotate", [{ value: 5, id: 91 }], 12);
                await store.uploadDirectoryPrekeys(
                    signedDelivery(accountSecret, [], { id: 92 }),
                    rotated,
                    NOW,
                );
                expect(
                    (
                        await store.claimDirectory(
                            account,
                            ticket,
                            NOW,
                            LIMITS,
                            ADMISSION_PRINCIPAL,
                        )
                    ).devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "one_time", keyPackage: new Uint8Array([5]) });
                expect(
                    (
                        await store.claimDirectory(
                            account,
                            ticket,
                            NOW,
                            LIMITS,
                            ADMISSION_PRINCIPAL,
                        )
                    ).devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "last_resort", keyPackage: new Uint8Array([12]) });
                const recoveredRotation = upload(
                    first,
                    firstSecret,
                    0,
                    "rotate",
                    [{ value: 6, id: 95 }],
                    12,
                );
                await expect(
                    store.uploadDirectoryPrekeys(
                        signedDelivery(accountSecret, [], { id: 96 }),
                        recoveredRotation,
                        NOW,
                    ),
                ).resolves.toBeUndefined();
                expect(
                    (
                        await store.claimDirectory(
                            account,
                            ticket,
                            NOW,
                            LIMITS,
                            ADMISSION_PRINCIPAL,
                        )
                    ).devices.find(
                        (device) => encodeBase64Url(device.deviceKey) === encodeBase64Url(first),
                    ),
                ).toMatchObject({ source: "one_time", keyPackage: new Uint8Array([6]) });
                await expect(
                    store.uploadDirectoryPrekeys(firstOuter, firstRotation, NOW),
                ).rejects.toMatchObject({ status: 409, body: { error: "replay" } });

                const firstQueue = await store.readQueue(first, null, 20, NOW, PAGE);
                expect(firstQueue.deliveries.map(({ delivery }) => delivery.id)).toEqual(
                    expect.arrayContaining([
                        firstRotation.oneTimePrekeys[0]!.spentNotification.id,
                        firstRotation.oneTimePrekeys[1]!.spentNotification.id,
                        replenishment.oneTimePrekeys[0]!.spentNotification.id,
                    ]),
                );
                const secondQueue = await store.readQueue(second, null, 20, NOW, PAGE);
                expect(secondQueue.deliveries.map(({ delivery }) => delivery.id)).toContain(
                    secondRotation.oneTimePrekeys[0]!.spentNotification.id,
                );
            } finally {
                await store.close();
            }
        }
    });

    test("stores one replay-protected current roster and rejects stale account targeting", async () => {
        const accountSecret = secret(91);
        const account = identity(accountSecret);
        const first = identity(secret(92));
        const second = identity(secret(93));
        const mutationBytes = (
            type: "register" | "remove",
            deviceKey: Uint8Array,
            resetGeneration: number,
        ): Uint8Array =>
            canonicalJson({
                version: 1,
                type,
                deviceKey: encodeBase64Url(deviceKey),
                resetGeneration,
                ...(type === "register"
                    ? { keyPackage: encodeBase64Url(new Uint8Array([resetGeneration + 1])) }
                    : {}),
            });
        for (const store of await stores()) {
            try {
                const firstMutation = signedDelivery(accountSecret, recipients(first), {
                    id: 91,
                    ciphertext: mutationBytes("register", first, 0),
                });
                await expect(
                    store.mutateDeviceRoster(
                        firstMutation,
                        {
                            version: 1,
                            type: "register",
                            deviceKey: first,
                            resetGeneration: 0,
                            keyPackage: new Uint8Array([1]),
                        },
                        NOW,
                        { ...LIMITS, maximumGlobalItems: 0 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 503, body: { error: "relay_full" } });
                await expect(store.readDeviceRoster(account)).resolves.toBeUndefined();
                const firstRoster = await store.mutateDeviceRoster(
                    firstMutation,
                    {
                        version: 1,
                        type: "register",
                        deviceKey: first,
                        resetGeneration: 0,
                        keyPackage: new Uint8Array([1]),
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                expect(firstRoster).toMatchObject({ revision: 1 });
                await expect(
                    store.mutateDeviceRoster(
                        firstMutation,
                        {
                            version: 1,
                            type: "register",
                            deviceKey: first,
                            resetGeneration: 0,
                            keyPackage: new Uint8Array([1]),
                        },
                        NOW,
                        LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 409, body: { error: "replay" } });

                const currentRecipients = recipients(first, second);
                const secondMutation = signedDelivery(accountSecret, currentRecipients, {
                    id: 92,
                    ciphertext: mutationBytes("register", second, 0),
                });
                const secondRoster = await store.mutateDeviceRoster(
                    secondMutation,
                    {
                        version: 1,
                        type: "register",
                        deviceKey: second,
                        resetGeneration: 0,
                        keyPackage: new Uint8Array([1]),
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                expect(secondRoster.devices).toHaveLength(2);

                await expect(
                    store.publish(
                        signedDelivery(secret(94), recipients(first), {
                            id: 93,
                            targetAccounts: [{ accountKey: account, rosterRevision: 1 }],
                        }),
                        NOW,
                        LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 409, body: { error: "stale_roster" } });

                const converged = signedDelivery(secret(94), currentRecipients, {
                    id: 94,
                    targetAccounts: [{ accountKey: account, rosterRevision: 2 }],
                });
                await expect(
                    store.publish(converged, NOW, LIMITS, ADMISSION_PRINCIPAL),
                ).resolves.toMatchObject({ duplicate: false });

                const reset = signedDelivery(accountSecret, currentRecipients, {
                    id: 95,
                    ciphertext: mutationBytes("register", second, 1),
                });
                expect(
                    (
                        await store.mutateDeviceRoster(
                            reset,
                            {
                                version: 1,
                                type: "register",
                                deviceKey: second,
                                resetGeneration: 1,
                                keyPackage: new Uint8Array([2]),
                            },
                            NOW,
                            LIMITS,
                            ADMISSION_PRINCIPAL,
                        )
                    ).devices.find(
                        (entry) => encodeBase64Url(entry.deviceKey) === encodeBase64Url(second),
                    )?.resetGeneration,
                ).toBe(1);

                const removal = signedDelivery(accountSecret, recipients(first), {
                    id: 96,
                    ciphertext: mutationBytes("remove", second, 1),
                });
                expect(
                    (
                        await store.mutateDeviceRoster(
                            removal,
                            {
                                version: 1,
                                type: "remove",
                                deviceKey: second,
                                resetGeneration: 1,
                            },
                            NOW,
                            LIMITS,
                            ADMISSION_PRINCIPAL,
                        )
                    ).devices,
                ).toHaveLength(1);
                await expect(
                    store.publish(
                        signedDelivery(secret(94), currentRecipients, {
                            id: 97,
                            targetAccounts: [{ accountKey: account, rosterRevision: 4 }],
                        }),
                        NOW,
                        LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 409, body: { error: "stale_roster" } });
                await expect(
                    store.publish(
                        signedDelivery(secret(94), recipients(first), {
                            id: 98,
                            targetAccounts: [{ accountKey: account, rosterRevision: 4 }],
                        }),
                        NOW,
                        LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).resolves.toMatchObject({ duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("strictly parses the configured backend and rejects an incomplete SQLite schema", () => {
        expect(parseRelayStoreBackend(undefined)).toBe("sqlite");
        expect(parseRelayStoreBackend("postgres")).toBe("postgres");
        expect(() => parseRelayStoreBackend("Postgres")).toThrow("exactly sqlite or postgres");

        const database = new DatabaseSync(":memory:");
        database.exec("CREATE TABLE murmur_queue_partial (id TEXT PRIMARY KEY)");
        expect(() => new SqliteRelayStore(":memory:", { database })).toThrow("Incomplete");
        database.close();
    });

    test("rejects a mismatched schema version without rewriting it", async () => {
        const sqlite = new DatabaseSync(":memory:");
        const sqliteStore = new SqliteRelayStore(":memory:", { database: sqlite });
        sqlite.exec("UPDATE murmur_queue_schema SET version = 2 WHERE singleton = 1");
        expect(() => new SqliteRelayStore(":memory:", { database: sqlite })).toThrow(
            "Unsupported SQLite queue schema version",
        );
        await sqliteStore.close();

        const pglite = new PGliteDatabase(new PGlite());
        const postgresStore = await PostgresRelayStore.create(pglite);
        await pglite.query("UPDATE murmur_queue_schema SET version = 2 WHERE singleton = 1");
        await expect(PostgresRelayStore.create(pglite)).rejects.toThrow(
            "Unsupported Postgres queue schema version",
        );
        await postgresStore.close();
    });

    test("atomically multicasts one event ID and trims each recipient independently", async () => {
        const aliceSecret = secret(1);
        const bobSecret = secret(2);
        const carolSecret = secret(3);
        const alice = identity(aliceSecret);
        const bob = identity(bobSecret);
        const carol = identity(carolSecret);
        for (const store of await stores()) {
            try {
                const delivery = signedDelivery(aliceSecret, recipients(alice, bob, carol));
                const published = await store.publish(delivery, NOW, LIMITS, ADMISSION_PRINCIPAL);
                expect(published.duplicate).toBe(false);
                expect(
                    await store.publish(delivery, NOW, LIMITS, ADMISSION_PRINCIPAL),
                ).toMatchObject({ eventId: published.eventId, duplicate: true });
                for (const recipient of [alice, bob, carol]) {
                    const page = await store.readQueue(recipient, null, 10, NOW, PAGE);
                    expect(page.deliveries.map(({ eventId: id }) => id)).toEqual([
                        published.eventId,
                    ]);
                    expect(page.head).toBe(published.eventId);
                }

                expect(await store.acknowledge(bob, published.eventId, NOW)).toMatchObject({
                    removed: 1,
                    sequence: 1,
                });
                expect(
                    (await store.readQueue(bob, published.eventId, 10, NOW, PAGE)).deliveries,
                ).toEqual([]);
                expect((await store.readQueue(alice, null, 10, NOW, PAGE)).deliveries).toHaveLength(
                    1,
                );
                await store.acknowledge(alice, published.eventId, NOW);
                await store.acknowledge(carol, published.eventId, NOW);
                await expect(store.acknowledge(alice, eventId(0), NOW)).rejects.toMatchObject({
                    status: 409,
                    body: { error: "ack_regression" },
                });

                const republished = await store.publish(delivery, NOW, LIMITS, ADMISSION_PRINCIPAL);
                expect(republished.duplicate).toBe(false);
                expect(republished.eventId > published.eventId).toBe(true);
            } finally {
                await store.close();
            }
        }
    });

    test("deletes only exact owner-session deliveries, advances continuity, and rejects replay", async () => {
        const owner = identity(secret(40));
        const otherOwner = identity(secret(41));
        const senderSecret = secret(42);
        const bob = identity(secret(43));
        const carol = identity(secret(44));
        const firstSession = new Uint8Array(32).fill(45);
        const secondSession = new Uint8Array(32).fill(46);
        const requestId = signedDelivery(secret(40), [], { id: 47 }).id;
        for (const store of await stores()) {
            try {
                await store.publish(
                    signedDelivery(senderSecret, recipients(bob, carol), {
                        id: 48,
                        ownerAccount: owner,
                        sessionId: firstSession,
                    }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await store.publish(
                    signedDelivery(senderSecret, recipients(bob), {
                        id: 49,
                        ownerAccount: owner,
                        sessionId: secondSession,
                    }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await store.publish(
                    signedDelivery(senderSecret, recipients(bob), {
                        id: 50,
                        ownerAccount: otherOwner,
                        sessionId: firstSession,
                    }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const bobBefore = await store.readQueue(bob, null, 10, NOW, PAGE);
                const carolBefore = await store.readQueue(carol, null, 10, NOW, PAGE);

                await expect(
                    store.deleteSessionDeliveries(owner, firstSession, requestId, NOW),
                ).resolves.toBe(1);
                const bobAfter = await store.readQueue(bob, null, 10, NOW, PAGE);
                const carolAfter = await store.readQueue(carol, null, 10, NOW, PAGE);
                expect(bobAfter.deliveries).toHaveLength(2);
                expect(carolAfter.deliveries).toHaveLength(0);
                expect(encodeBase64Url(bobAfter.generation)).not.toBe(
                    encodeBase64Url(bobBefore.generation),
                );
                expect(encodeBase64Url(carolAfter.generation)).not.toBe(
                    encodeBase64Url(carolBefore.generation),
                );
                await expect(
                    store.deleteSessionDeliveries(owner, firstSession, requestId, NOW),
                ).rejects.toMatchObject({ status: 409, body: { error: "replay" } });
            } finally {
                await store.close();
            }
        }
    });

    test("terminally deletes account-owned state without exposing account existence", async () => {
        const accountSecret = secret(101);
        const account = identity(accountSecret);
        const deviceSecret = secret(102);
        const device = identity(deviceSecret);
        const survivor = identity(secret(103));
        const externalSecret = secret(104);
        const external = identity(externalSecret);
        const mutation = canonicalJson({
            version: 1,
            type: "register",
            deviceKey: encodeBase64Url(device),
            resetGeneration: 0,
            keyPackage: encodeBase64Url(new Uint8Array([1])),
        });
        for (const store of await stores()) {
            try {
                await store.mutateDeviceRoster(
                    signedDelivery(accountSecret, recipients(device), {
                        id: 105,
                        ciphertext: mutation,
                    }),
                    {
                        version: 1,
                        type: "register",
                        deviceKey: device,
                        resetGeneration: 0,
                        keyPackage: new Uint8Array([1]),
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await store.publish(
                    signedDelivery(deviceSecret, recipients(survivor), {
                        id: 106,
                        senderAccount: account,
                    }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await store.publish(
                    signedDelivery(externalSecret, recipients(device, survivor), { id: 107 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                await store.deleteSessionDeliveries(
                    account,
                    new Uint8Array(32).fill(108),
                    signedDelivery(accountSecret, [], { id: 108 }).id,
                    NOW,
                );
                const before = await store.readQueue(survivor, null, 10, NOW, PAGE);
                const requestId = signedDelivery(accountSecret, [], { id: 109 }).id;
                await expect(store.deleteAccountState(account, requestId, NOW)).resolves.toBe(
                    undefined,
                );
                expect(await store.readDeviceRoster(account)).toBeUndefined();
                expect((await store.readQueue(device, null, 10, NOW, PAGE)).deliveries).toEqual([]);
                const after = await store.readQueue(survivor, null, 10, NOW, PAGE);
                expect(after.deliveries).toHaveLength(1);
                expect(after.deliveries[0]?.delivery.sender).toEqual(external);
                expect(encodeBase64Url(after.generation)).not.toBe(
                    encodeBase64Url(before.generation),
                );
                await expect(
                    store.deleteAccountState(account, requestId, NOW),
                ).rejects.toMatchObject({ status: 409, body: { error: "replay" } });

                const absent = identity(secret(110));
                const absentRequest = signedDelivery(secret(110), [], { id: 110 }).id;
                await expect(store.deleteAccountState(absent, absentRequest, NOW)).resolves.toBe(
                    undefined,
                );
                expect(await store.readDeviceRoster(absent)).toBeUndefined();

                const deletedClaim = await store.claimDirectory(
                    account,
                    {
                        issuer: "account-deletion-test",
                        ticketId: new Uint8Array(32).fill(121),
                        expiresAt: NOW + 1_000,
                        claimBudget: 1,
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const absentClaim = await store.claimDirectory(
                    absent,
                    {
                        issuer: "account-deletion-test",
                        ticketId: new Uint8Array(32).fill(122),
                        expiresAt: NOW + 1_000,
                        claimBudget: 1,
                    },
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                expect(deletedClaim).toEqual({
                    version: 1,
                    accountKey: account,
                    rosterRevision: 0,
                    devices: [],
                });
                expect(absentClaim).toEqual({
                    version: 1,
                    accountKey: absent,
                    rosterRevision: 0,
                    devices: [],
                });
            } finally {
                await store.close();
            }
        }
    });

    test("leaves no raw SQLite account rows after the terminal cascade", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const accountSecret = secret(111);
        const account = identity(accountSecret);
        const deviceSecret = secret(112);
        const device = identity(deviceSecret);
        const survivor = identity(secret(113));
        try {
            await store.mutateDeviceRoster(
                signedDelivery(accountSecret, recipients(device), { id: 114 }),
                {
                    version: 1,
                    type: "register",
                    deviceKey: device,
                    resetGeneration: 0,
                    keyPackage: new Uint8Array([1]),
                },
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            const directoryReference = new Uint8Array(32).fill(118);
            const spentNotification = signedDelivery(deviceSecret, recipients(device), {
                id: 118,
                senderAccount: account,
                ciphertext: canonicalJson({
                    version: 1,
                    type: "directory_prekey_spent",
                    reference: encodeBase64Url(directoryReference),
                }),
                expiresAt: NOW + 60_000,
            });
            await store.uploadDirectoryPrekeys(
                signedDelivery(accountSecret, [], { id: 119 }),
                {
                    version: 1,
                    type: "directory_prekey_upload",
                    mode: "rotate",
                    deviceKey: device,
                    resetGeneration: 0,
                    oneTimePrekeys: [
                        {
                            reference: directoryReference,
                            keyPackage: new Uint8Array([2]),
                            expiresAt: NOW + 60_000,
                            spentNotification,
                        },
                    ],
                    lastResort: {
                        reference: new Uint8Array(32).fill(120),
                        keyPackage: new Uint8Array([3]),
                        expiresAt: NOW + 60_000,
                    },
                },
                NOW,
            );
            await store.publish(
                signedDelivery(deviceSecret, recipients(device, survivor), {
                    id: 115,
                    senderAccount: account,
                }),
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            await store.deleteSessionDeliveries(
                account,
                new Uint8Array(32).fill(116),
                signedDelivery(accountSecret, [], { id: 116 }).id,
                NOW,
            );
            const ownedSession = new Uint8Array(32).fill(121);
            await store.publish(
                signedDelivery(deviceSecret, [], {
                    id: 121,
                    senderAccount: account,
                    ownerAccount: account,
                    sessionId: ownedSession,
                    sessionControl: {
                        version: 1,
                        type: "create",
                        epoch: 0n,
                        members: [account],
                        roles: {
                            owner: account,
                            admins: [],
                            adminsAssignAdmins: false,
                            anyoneCanAddMembers: false,
                            sendPolicy: "everyone",
                        },
                        coveredDevices: [device],
                    },
                }),
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            expect(await store.readSessionState(ownedSession)).toBeDefined();
            await store.deleteAccountState(
                account,
                signedDelivery(accountSecret, [], { id: 117 }).id,
                NOW,
            );
            const accountTables = [
                ["murmur_device_rosters", "account_key"],
                ["murmur_device_roster_devices", "account_key"],
                ["murmur_device_roster_nonces", "account_key"],
                ["murmur_directory_devices", "account_key"],
                ["murmur_directory_prekeys", "account_key"],
                ["murmur_directory_prekey_references", "account_key"],
                ["murmur_directory_upload_nonces", "account_key"],
                ["murmur_session_deletion_nonces", "owner_account"],
                ["murmur_sessions", "owner_account"],
                ["murmur_session_members", "account_key"],
                ["murmur_session_admins", "account_key"],
                ["murmur_queue_deliveries", "sender_account"],
            ] as const;
            for (const [table, column] of accountTables) {
                expect(
                    database
                        .prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${column} = ?`)
                        .get(account),
                ).toEqual({ count: 0 });
            }
            expect(
                database
                    .prepare(
                        `SELECT
                            (SELECT COUNT(*) FROM murmur_queues WHERE recipient IN (?, ?)) AS queues,
                            (SELECT COUNT(*) FROM murmur_queue_references
                             WHERE recipient IN (?, ?)) AS refs,
                            (SELECT COUNT(*) FROM murmur_account_deletion_nonces) AS tombstones,
                            (SELECT pending_items FROM murmur_queue_global) AS pending_items,
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS actual_items,
                            (SELECT pending_references FROM murmur_queue_global) AS pending_refs,
                            (SELECT COUNT(*) FROM murmur_queue_references) AS actual_refs`,
                    )
                    .get(account, device, account, device),
            ).toEqual({
                queues: 0,
                refs: 0,
                tombstones: 1,
                pending_items: 0,
                actual_items: 0,
                pending_refs: 0,
                actual_refs: 0,
            });
        } finally {
            await store.close();
        }
    });

    test("rejects pending ID collisions and all-or-nothing queue overflow", async () => {
        const aliceSecret = secret(4);
        const bob = identity(secret(5));
        const carol = identity(secret(6));
        for (const store of await stores()) {
            try {
                const first = signedDelivery(aliceSecret, recipients(bob), { id: 7 });
                const firstOutcome = await store.publish(
                    first,
                    NOW,
                    {
                        ...LIMITS,
                        maximumItems: 1,
                    },
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(bob), {
                            id: 7,
                            ciphertext: new Uint8Array([99]),
                        }),
                        NOW,
                        LIMITS,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 409 });
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(bob, carol), { id: 8 }),
                        NOW,
                        { ...LIMITS, maximumItems: 1 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429 });
                expect(await store.readQueue(carol, null, 10, NOW, PAGE)).toMatchObject({
                    deliveries: [],
                    head: null,
                });
                await store.acknowledge(bob, firstOutcome.eventId, NOW);
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(bob, carol), { id: 8 }),
                        NOW,
                        { ...LIMITS, maximumItems: 1 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).resolves.toMatchObject({ duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("expiration destructively removes pending inbox data", async () => {
        const aliceSecret = secret(7);
        const bob = identity(secret(8));
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(aliceSecret, recipients(bob), {
                        expiresAt: NOW + 1,
                    }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const expired = await store.readQueue(bob, null, 10, NOW + 2, PAGE);
                expect(expired).toMatchObject({
                    deliveries: [],
                    head: published.eventId,
                    acknowledgedThrough: null,
                    headSequence: 1,
                    exhausted: true,
                });
                await store.acknowledge(bob, published.eventId, NOW + 2);
                const baseline = await store.readQueue(bob, published.eventId, 10, NOW + 2, PAGE);
                expect(baseline).toMatchObject({
                    deliveries: [],
                    head: published.eventId,
                    acknowledgedThrough: published.eventId,
                    acknowledgedSequence: 1,
                    exhausted: true,
                });
            } finally {
                await store.close();
            }
        }
    });

    test("declared restore changes generations without deleting pending data", async () => {
        const aliceSecret = secret(40);
        const bob = identity(secret(41));
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(aliceSecret, recipients(bob), { id: 42 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                const before = await store.readQueue(bob, null, 10, NOW, PAGE);
                await expect(store.declareRestored()).resolves.toBeGreaterThanOrEqual(1);
                const after = await store.readQueue(bob, null, 10, NOW, PAGE);
                expect(after.deliveries.map((delivery) => delivery.eventId)).toEqual([
                    published.eventId,
                ]);
                expect(after.headSequence).toBe(before.headSequence);
                expect(after.generation).not.toEqual(before.generation);
            } finally {
                await store.close();
            }
        }
    });

    test("enforces sender and global pending-storage quotas transactionally", async () => {
        const aliceSecret = secret(15);
        const bobSecret = secret(16);
        const recipient = identity(secret(17));
        for (const store of await stores()) {
            try {
                const limits = {
                    ...LIMITS,
                    maximumSenderItems: 1,
                    maximumGlobalItems: 1,
                };
                await store.publish(
                    signedDelivery(aliceSecret, recipients(recipient), { id: 18 }),
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.publish(
                        signedDelivery(aliceSecret, recipients(recipient), { id: 19 }),
                        NOW,
                        { ...limits, maximumGlobalItems: 10 },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429, body: { error: "sender_full" } });
                await expect(
                    store.publish(
                        signedDelivery(bobSecret, recipients(recipient), { id: 20 }),
                        NOW,
                        limits,
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 503, body: { error: "relay_full" } });
                expect(
                    (await store.readQueue(recipient, null, 10, NOW, PAGE)).deliveries,
                ).toHaveLength(1);
            } finally {
                await store.close();
            }
        }
    });

    test("charges multicast fanout against the sender reference quota", async () => {
        const sender = secret(27);
        const first = identity(secret(28));
        const second = identity(secret(29));
        for (const store of await stores()) {
            try {
                await store.publish(
                    signedDelivery(sender, recipients(first, second), { id: 30 }),
                    NOW,
                    { ...LIMITS, maximumSenderReferences: 2 },
                    ADMISSION_PRINCIPAL,
                );
                await expect(
                    store.publish(
                        signedDelivery(sender, recipients(first), { id: 31 }),
                        NOW,
                        {
                            ...LIMITS,
                            maximumSenderReferences: 2,
                        },
                        ADMISSION_PRINCIPAL,
                    ),
                ).rejects.toMatchObject({ status: 429, body: { error: "sender_full" } });
            } finally {
                await store.close();
            }
        }
    });

    test("bounds exact outstanding fanout per admitted ingress principal", async () => {
        const firstSender = secret(32);
        const secondSender = secret(33);
        const first = identity(secret(34));
        const second = identity(secret(35));
        const principal = new Uint8Array(32).fill(36);
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(firstSender, recipients(first, second), { id: 37 }),
                    NOW,
                    { ...LIMITS, maximumAdmissionReferences: 2 },
                    principal,
                );
                await expect(
                    store.publish(
                        signedDelivery(secondSender, recipients(first), { id: 38 }),
                        NOW,
                        { ...LIMITS, maximumAdmissionReferences: 2 },
                        principal,
                    ),
                ).rejects.toMatchObject({ status: 429, body: { error: "admission_full" } });

                await store.acknowledge(first, published.eventId, NOW);
                await store.acknowledge(second, published.eventId, NOW);
                await expect(
                    store.publish(
                        signedDelivery(secondSender, recipients(first), { id: 38 }),
                        NOW,
                        { ...LIMITS, maximumAdmissionReferences: 2 },
                        principal,
                    ),
                ).resolves.toMatchObject({ duplicate: false });
            } finally {
                await store.close();
            }
        }
    });

    test("multicast UUIDv7 IDs are monotonic within every recipient inbox", async () => {
        const aliceSecret = secret(9);
        const bobSecret = secret(10);
        const alice = identity(aliceSecret);
        const bob = identity(bobSecret);
        const store = await PostgresRelayStore.create(new PGliteDatabase(new PGlite()));
        try {
            const targets = recipients(alice, bob);
            await Promise.all([
                store.publish(
                    signedDelivery(aliceSecret, targets, { id: 11 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                ),
                store.publish(
                    signedDelivery(bobSecret, targets, { id: 12 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                ),
            ]);
            const aliceOrder = (await store.readQueue(alice, null, 10, NOW, PAGE)).deliveries.map(
                ({ eventId }) => eventId,
            );
            const bobOrder = (await store.readQueue(bob, null, 10, NOW, PAGE)).deliveries.map(
                ({ eventId }) => eventId,
            );
            expect(aliceOrder).toHaveLength(2);
            expect(aliceOrder[1]! > aliceOrder[0]!).toBe(true);
            expect(bobOrder).toEqual(aliceOrder);
        } finally {
            await store.close();
        }
    });

    test("set-based multicast handles a broad recipient fanout", async () => {
        const sender = secret(23);
        const targets = recipients(
            ...Array.from({ length: 64 }, (_, index) => identity(secret(24 + index))),
        );
        for (const store of await stores()) {
            try {
                const published = await store.publish(
                    signedDelivery(sender, targets, { id: 90 }),
                    NOW,
                    LIMITS,
                    ADMISSION_PRINCIPAL,
                );
                for (const target of [targets[0]!, targets.at(-1)!]) {
                    const page = await store.readQueue(target, null, 10, NOW, PAGE);
                    expect(page.deliveries.map(({ eventId }) => eventId)).toEqual([
                        published.eventId,
                    ]);
                }
            } finally {
                await store.close();
            }
        }
    });

    test("reclaims all SQLite queue metadata after acknowledgement or expiration", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const aliceSecret = secret(11);
        const recipient = identity(secret(12));
        try {
            const published = await store.publish(
                signedDelivery(aliceSecret, recipients(recipient), { id: 13 }),
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            await store.acknowledge(recipient, published.eventId, NOW);
            expect(
                database
                    .prepare(
                        `SELECT
                            (SELECT COUNT(*) FROM murmur_queues) AS queues,
                            (SELECT COUNT(*) FROM murmur_queue_references) AS refs,
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS deliveries,
                            (SELECT pending_items FROM murmur_queue_global) AS pending_items,
                            (SELECT pending_references
                             FROM murmur_queue_global) AS pending_refs`,
                    )
                    .get(),
            ).toEqual({
                queues: 1,
                refs: 0,
                deliveries: 0,
                pending_items: 0,
                pending_refs: 0,
            });

            await store.publish(
                signedDelivery(aliceSecret, recipients(recipient), {
                    id: 14,
                    expiresAt: NOW + 1,
                }),
                NOW,
                LIMITS,
                ADMISSION_PRINCIPAL,
            );
            await store.pruneExpired(NOW + 2);
            expect(
                database
                    .prepare(
                        `SELECT
                            (SELECT COUNT(*) FROM murmur_queues) AS queues,
                            (SELECT COUNT(*) FROM murmur_queue_references) AS refs,
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS deliveries,
                            (SELECT pending_items FROM murmur_queue_global) AS pending_items,
                            (SELECT pending_references
                             FROM murmur_queue_global) AS pending_refs`,
                    )
                    .get(),
            ).toEqual({
                queues: 1,
                refs: 0,
                deliveries: 0,
                pending_items: 0,
                pending_refs: 0,
            });
        } finally {
            await store.close();
        }
    });

    test("bounds each SQLite expiration transaction to one fixed delivery batch", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const sender = secret(21);
        const recipient = identity(secret(22));
        const limits = {
            ...LIMITS,
            maximumItems: 200,
            maximumSenderItems: 200,
            maximumGlobalItems: 200,
        };
        try {
            for (let index = 1; index <= 101; index += 1) {
                await store.publish(
                    signedDelivery(sender, recipients(recipient), {
                        id: index,
                        expiresAt: NOW + 1,
                    }),
                    NOW,
                    limits,
                    ADMISSION_PRINCIPAL,
                );
            }
            expect(await store.pruneExpired(NOW + 2)).toBe(100);
            const remaining = database
                .prepare(
                    `SELECT
                            (SELECT COUNT(*) FROM murmur_queue_deliveries) AS deliveries,
                            queue.pending_items,
                            queue.pending_bytes,
                            (SELECT COUNT(*) FROM murmur_queue_references
                             WHERE recipient = queue.recipient) AS actual_items,
                            (SELECT COALESCE(SUM(encoded_bytes), 0)
                             FROM murmur_queue_references
                             WHERE recipient = queue.recipient) AS actual_bytes
                         FROM murmur_queues AS queue
                         WHERE recipient = ?`,
                )
                .get(recipient);
            expect(remaining).toMatchObject({
                deliveries: 1,
                pending_items: 1,
                actual_items: 1,
            });
            expect(remaining?.pending_bytes).toBe(remaining?.actual_bytes);
            expect(await store.pruneExpired(NOW + 2)).toBe(1);
        } finally {
            await store.close();
        }
    });

    test("commits a bounded prune even when the following publication is rejected", async () => {
        const database = new DatabaseSync(":memory:");
        const store = new SqliteRelayStore(":memory:", { database });
        const sender = secret(91);
        const earlierRecipient = identity(secret(92));
        const targetRecipient = identity(secret(93));
        const setupLimits = {
            ...LIMITS,
            maximumItems: 200,
            maximumSenderItems: 200,
            maximumGlobalItems: 200,
        };
        try {
            for (let index = 1; index <= 100; index += 1) {
                await store.publish(
                    signedDelivery(sender, recipients(earlierRecipient), {
                        id: index,
                        expiresAt: NOW + 1,
                    }),
                    NOW,
                    setupLimits,
                    ADMISSION_PRINCIPAL,
                );
            }
            await store.publish(
                signedDelivery(sender, recipients(targetRecipient), {
                    id: 101,
                    expiresAt: NOW + 2,
                }),
                NOW,
                setupLimits,
                ADMISSION_PRINCIPAL,
            );
            const replacement = signedDelivery(sender, recipients(targetRecipient), {
                id: 102,
                expiresAt: NOW + 60_000,
            });
            await expect(
                store.publish(
                    replacement,
                    NOW + 3,
                    {
                        ...setupLimits,
                        maximumItems: 1,
                    },
                    ADMISSION_PRINCIPAL,
                ),
            ).rejects.toMatchObject({ status: 429, body: { error: "queue_full" } });
            expect(
                database.prepare("SELECT COUNT(*) AS count FROM murmur_queue_deliveries").get(),
            ).toEqual({ count: 1 });
            await expect(
                store.publish(
                    replacement,
                    NOW + 3,
                    {
                        ...setupLimits,
                        maximumItems: 1,
                    },
                    ADMISSION_PRINCIPAL,
                ),
            ).resolves.toMatchObject({ duplicate: false });
        } finally {
            await store.close();
        }
    });
});
