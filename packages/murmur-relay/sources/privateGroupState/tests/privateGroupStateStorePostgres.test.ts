import { PGlite } from "@electric-sql/pglite";
import { sha256 } from "@noble/hashes/sha2";
import { describe, expect, test } from "vitest";
import { PGliteDatabase } from "../../storage/index.js";
import {
    PostgresPrivateGroupStateStore,
    type PrivateGroupPresentationChallenge,
    type PrivateGroupStateLimits,
    type PrivateGroupStateRecord,
} from "../index.js";

const NOW = 1_800_000_000_000;
const LIMITS: PrivateGroupStateLimits = {
    maximumGroups: 10,
    maximumRecordBytes: 1_000_000,
    maximumSealedStateBytes: 500_000,
    maximumMembersPerGroup: 10,
    maximumPendingChallenges: 10,
};

function bytes(seed: number, length = 32): Uint8Array {
    return Uint8Array.from({ length }, (_, index) => (seed + index * 29) & 0xff);
}

function record(
    revision: number,
    previousRevisionHash: Uint8Array | null,
): PrivateGroupStateRecord {
    return {
        version: 1,
        opaqueGroupId: bytes(1),
        publicParameters: bytes(2, 96),
        revision,
        previousRevisionHash,
        members: [
            { entry: bytes(10, 48), role: "owner" },
            { entry: bytes(20, 48), role: "member" },
        ],
        sealedState: bytes(30, 128),
        revisionAuthenticator: bytes(40),
    };
}

describe("Postgres private-group state store", () => {
    test("persists monotonic canonical versions and makes exact retries idempotent", async () => {
        const database = new PGliteDatabase(new PGlite());
        let store = await PostgresPrivateGroupStateStore.create(database);
        try {
            const initialRecord = record(1, null);
            const initialRaw = bytes(50, 256);
            const initialHash = sha256(initialRaw);
            const initial = await store.create(initialRecord, initialHash, initialRaw, LIMITS, NOW);
            expect(initial.canonicalVersion).toMatch(
                /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
            );
            expect(initial.replacesVersion).toBeNull();
            expect(initial.commitEventId).toBeNull();
            expect(await store.create(initialRecord, initialHash, initialRaw, LIMITS, NOW)).toEqual(
                initial,
            );

            const successorRecord = record(2, initialHash);
            const successorRaw = bytes(60, 257);
            const successorHash = sha256(successorRaw);
            const successor = await store.replace(
                initial.canonicalVersion,
                initialHash,
                successorRecord,
                successorHash,
                successorRaw,
                LIMITS,
                NOW,
            );
            expect(successor.canonicalVersion > initial.canonicalVersion).toBe(true);
            expect(successor.replacesVersion).toBe(initial.canonicalVersion);
            expect(
                await store.replace(
                    initial.canonicalVersion,
                    initialHash,
                    successorRecord,
                    successorHash,
                    successorRaw,
                    LIMITS,
                    NOW,
                ),
            ).toEqual(successor);

            await expect(
                store.replace(
                    initial.canonicalVersion,
                    initialHash,
                    { ...successorRecord, sealedState: bytes(61, 257) },
                    sha256(bytes(61, 258)),
                    bytes(61, 258),
                    LIMITS,
                    NOW,
                ),
            ).rejects.toThrow("canonical version conflict");

            store.close();
            store = await PostgresPrivateGroupStateStore.create(database);
            expect(await store.read(initialRecord.opaqueGroupId)).toEqual(successor);
        } finally {
            store.close();
            await database.close();
        }
    });

    test("atomically consumes bounded expiring challenges", async () => {
        const database = new PGliteDatabase(new PGlite());
        const store = await PostgresPrivateGroupStateStore.create(database);
        try {
            const challenge: PrivateGroupPresentationChallenge = {
                opaqueGroupId: bytes(1),
                entry: bytes(2, 48),
                role: "owner",
                operation: "create",
                replayNonce: bytes(3),
                context: bytes(4, 96),
                expiresAt: NOW + 100,
            };
            await store.storeChallenge(challenge, 1, NOW);
            expect(await store.consumeChallenge(challenge.replayNonce, NOW)).toEqual(challenge);
            expect(await store.consumeChallenge(challenge.replayNonce, NOW)).toBeUndefined();

            await store.storeChallenge(challenge, 1, NOW);
            expect(
                await store.consumeChallenge(challenge.replayNonce, challenge.expiresAt),
            ).toBeUndefined();
        } finally {
            store.close();
            await database.close();
        }
    });

    test("rejects partial schemas instead of creating migration machinery", async () => {
        const postgres = new PGlite();
        await postgres.exec(
            "CREATE TABLE murmur_private_group_records (group_id bytea PRIMARY KEY)",
        );
        const database = new PGliteDatabase(postgres);
        await expect(PostgresPrivateGroupStateStore.create(database)).rejects.toThrow(
            "Incomplete Postgres private-group schema",
        );
        await database.close();
    });
});
