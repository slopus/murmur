import { describe, expect, it } from "vitest";
import {
    PrivateGroupStateService,
    SqlitePrivateGroupStateStore,
    encodePrivateGroupStateRecord as encodeServiceRecord,
} from "@slopus/murmur-relay";
import { deriveCredentialIssuer } from "../../privateGroups/index.js";
import { encodeBase64Url, equalBytes, utf8Encode } from "../../utils/index.js";
import {
    PrivateGroupStateClient,
    createPrivateGroupCredentialAuthority,
    privateGroupStateRecordHash,
    type PrivateGroupRecordContent,
    type PrivateGroupStateRecord,
    type StoredPrivateGroupStateRecord,
} from "../index.js";

const START = 1_800_000_000_000;

function bytes(seed: number): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, index) => (seed + index * 29) & 0xff);
}

function containsSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
    if (needle.length === 0 || needle.length > haystack.length) return false;
    for (let offset = 0; offset <= haystack.length - needle.length; offset += 1) {
        if (equalBytes(haystack.subarray(offset, offset + needle.length), needle)) return true;
    }
    return false;
}

interface Fixture {
    now: number;
    readonly accountA: Uint8Array;
    readonly accountB: Uint8Array;
    readonly accountC: Uint8Array;
    readonly store: SqlitePrivateGroupStateStore;
    readonly service: PrivateGroupStateService;
    readonly clientA: PrivateGroupStateClient;
    readonly clientB: PrivateGroupStateClient;
    readonly sessionAB: PrivateGroupRecordContent["session"];
    readonly rolesAB: PrivateGroupRecordContent["roles"];
    close(): void;
}

function fixture(groupSecret = bytes(101)): Fixture {
    const accountA = bytes(11);
    const accountB = bytes(12);
    const accountC = bytes(13);
    const issuer = deriveCredentialIssuer(bytes(91));
    const store = new SqlitePrivateGroupStateStore(":memory:");
    const clock = { now: START };
    const service = new PrivateGroupStateService({
        store,
        credentialAuthority: createPrivateGroupCredentialAuthority(issuer),
        tokenSecret: bytes(201),
        now: () => clock.now,
        challengeLifetimeMilliseconds: 10 * 60_000,
    });
    const clientA = new PrivateGroupStateClient({
        accountIdentifier: accountA,
        groupMasterSecret: groupSecret,
        transport: service,
        now: () => clock.now,
    });
    const clientB = new PrivateGroupStateClient({
        accountIdentifier: accountB,
        groupMasterSecret: groupSecret,
        transport: service,
        now: () => clock.now,
    });
    return {
        get now(): number {
            return clock.now;
        },
        set now(now: number) {
            clock.now = now;
        },
        accountA,
        accountB,
        accountC,
        store,
        service,
        clientA,
        clientB,
        sessionAB: {
            id: bytes(151),
            status: "active",
            descriptor: utf8Encode("private group session"),
            members: [accountA, accountB],
            owner: accountA,
            admins: [accountA],
            policies: { adminsAssignAdmins: false, anyoneCanAddMembers: false },
        },
        rolesAB: [
            { accountIdentifier: accountA, role: "owner" },
            { accountIdentifier: accountB, role: "member" },
        ],
        close: (): void => {
            clientA.close();
            clientB.close();
            service.close();
        },
    };
}

function content(
    value: Fixture,
    attributes: string,
    overrides: Partial<Pick<PrivateGroupRecordContent, "session" | "roles">> = {},
): PrivateGroupRecordContent {
    return {
        attributes: utf8Encode(attributes),
        session: overrides.session ?? value.sessionAB,
        roles: overrides.roles ?? value.rolesAB,
    };
}

async function createGroup(value: Fixture): Promise<{
    readonly credentialA: Awaited<ReturnType<PrivateGroupStateClient["obtainCredential"]>>;
    readonly initial: StoredPrivateGroupStateRecord;
}> {
    const credentialA = await value.clientA.obtainCredential(utf8Encode("auth/session/A"));
    const accepted = await value.clientA.createGroup(credentialA, content(value, "title: alpha"));
    return { credentialA, initial: accepted.record };
}

function stored(
    record: PrivateGroupStateRecord,
    canonical: StoredPrivateGroupStateRecord,
): StoredPrivateGroupStateRecord {
    return {
        record,
        revisionHash: privateGroupStateRecordHash(record),
        canonicalVersion: canonical.canonicalVersion,
        replacesVersion: canonical.replacesVersion,
        commitEventId: canonical.commitEventId,
    };
}

describe("private-group canonical state service", () => {
    it("creates opaque state, admits another member anonymously, rejects duplicates, and unlinks groups", async () => {
        const value = fixture();
        try {
            const created = await createGroup(value);
            const credentialB = await value.clientB.obtainCredential(utf8Encode("auth/session/B"));
            const memberToken = await value.clientB.authorize(credentialB, "member", "access");
            const read = await value.clientB.readGroup(memberToken, {
                session: value.sessionAB,
                roles: value.rolesAB,
            });
            expect(new TextDecoder().decode(read.attributes)).toBe("title: alpha");

            const persisted = value.store.read(value.clientA.opaqueGroupId);
            expect(persisted).toBeDefined();
            const raw = encodeServiceRecord(persisted!.record);
            expect(containsSequence(raw, utf8Encode("title: alpha"))).toBe(false);
            for (const account of [value.accountA, value.accountB]) {
                expect(containsSequence(raw, account)).toBe(false);
                expect(containsSequence(raw, utf8Encode(encodeBase64Url(account)))).toBe(false);
                expect(
                    persisted!.record.members.some((member) => equalBytes(member.entry, account)),
                ).toBe(false);
            }

            const duplicate: PrivateGroupStateRecord = {
                ...created.initial.record,
                revision: 2,
                previousRevisionHash: created.initial.revisionHash,
                members: [created.initial.record.members[0]!, created.initial.record.members[0]!],
            };
            const ownerToken = await value.clientA.authorize(
                created.credentialA,
                "owner",
                "access",
            );
            await expect(
                value.service.replaceRecord({
                    replacesVersion: created.initial.canonicalVersion,
                    expectedRevisionHash: created.initial.revisionHash,
                    record: duplicate,
                    token: ownerToken.bytes,
                }),
            ).rejects.toThrow("unique and canonically ordered");

            const otherGroup = fixture(bytes(102));
            try {
                expect(
                    equalBytes(
                        value.clientA.ownEncryptedEntry,
                        otherGroup.clientA.ownEncryptedEntry,
                    ),
                ).toBe(false);
            } finally {
                otherGroup.close();
            }
        } finally {
            value.close();
        }
    });

    it("enforces token group, role, and expiry scopes", async () => {
        const value = fixture();
        try {
            const created = await createGroup(value);
            const credentialA = created.credentialA;
            const credentialB = await value.clientB.obtainCredential(utf8Encode("auth/session/B"));
            const ownerToken = await value.clientA.authorize(credentialA, "owner", "access");
            const memberToken = await value.clientB.authorize(credentialB, "member", "access");

            const otherGroup = fixture(bytes(103));
            try {
                await createGroup(otherGroup);
                await expect(
                    otherGroup.service.readRecord({
                        opaqueGroupId: otherGroup.clientA.opaqueGroupId,
                        token: ownerToken.bytes,
                    }),
                ).rejects.toThrow("wrong group scope");
            } finally {
                otherGroup.close();
            }

            const successor = value.clientA.buildSuccessorRecord(
                created.initial,
                content(value, "title: beta"),
            );
            await expect(
                value.service.replaceRecord({
                    replacesVersion: created.initial.canonicalVersion,
                    expectedRevisionHash: created.initial.revisionHash,
                    record: successor,
                    token: memberToken.bytes,
                }),
            ).rejects.toThrow("requires owner or administrator role");

            value.now = ownerToken.expiresAt;
            await expect(
                value.service.readRecord({
                    opaqueGroupId: value.clientA.opaqueGroupId,
                    token: ownerToken.bytes,
                }),
            ).rejects.toThrow("expired");
        } finally {
            value.close();
        }
    });

    it("rejects replayed presentations and credentials after expiry", async () => {
        const value = fixture();
        try {
            const credential = await value.clientA.obtainCredential(utf8Encode("auth/session/A"));
            const validChallenge = await value.service.createPresentationChallenge({
                opaqueGroupId: value.clientA.opaqueGroupId,
                entry: value.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "create",
            });
            const validPresentation = value.clientA.createPresentation(credential, validChallenge);
            const publicParameters = value.clientA.buildInitialRecord(
                content(value, "title: alpha"),
            ).publicParameters;
            await value.service.authenticatePresentation({
                challenge: validChallenge,
                publicParameters,
                presentation: validPresentation,
            });
            await expect(
                value.service.authenticatePresentation({
                    challenge: validChallenge,
                    publicParameters,
                    presentation: validPresentation,
                }),
            ).rejects.toThrow("invalid or replayed");

            const expiryChallenge = await value.service.createPresentationChallenge({
                opaqueGroupId: value.clientA.opaqueGroupId,
                entry: value.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "create",
            });
            const expiryPresentation = value.clientA.createPresentation(
                credential,
                expiryChallenge,
            );
            value.now = credential.expiresAt;
            await expect(
                value.service.authenticatePresentation({
                    challenge: expiryChallenge,
                    publicParameters,
                    presentation: expiryPresentation,
                }),
            ).rejects.toThrow("Invalid or expired");
            expect(() => value.clientA.createPresentation(credential, expiryChallenge)).toThrow(
                "expired credential",
            );
        } finally {
            value.close();
        }
    });

    it("rejects a roster revision that is not reflected in the reader's MLS state", async () => {
        const value = fixture();
        try {
            const created = await createGroup(value);
            const credentialB = await value.clientB.obtainCredential(utf8Encode("auth/session/B"));
            const memberToken = await value.clientB.authorize(credentialB, "member", "access");
            await value.clientB.readGroup(memberToken, {
                session: value.sessionAB,
                roles: value.rolesAB,
            });
            const ownerToken = await value.clientA.authorize(
                created.credentialA,
                "owner",
                "access",
            );
            const sessionABC: PrivateGroupRecordContent["session"] = {
                ...value.sessionAB,
                members: [value.accountA, value.accountB, value.accountC],
            };
            const rolesABC: PrivateGroupRecordContent["roles"] = [
                ...value.rolesAB,
                { accountIdentifier: value.accountC, role: "member" },
            ];
            const successor = value.clientA.buildSuccessorRecord(
                created.initial,
                content(value, "title: unauthorized roster", {
                    session: sessionABC,
                    roles: rolesABC,
                }),
            );
            await value.service.replaceRecord({
                replacesVersion: created.initial.canonicalVersion,
                expectedRevisionHash: created.initial.revisionHash,
                record: successor,
                token: ownerToken.bytes,
            });
            await expect(
                value.clientB.readGroup(memberToken, {
                    session: value.sessionAB,
                    roles: value.rolesAB,
                }),
            ).rejects.toThrow("roster is not reflected in authenticated MLS state");
        } finally {
            value.close();
        }
    });
    it("rejects canonical rollback and fork revisions at the client", async () => {
        const value = fixture();
        try {
            const created = await createGroup(value);
            const ownerToken = await value.clientA.authorize(
                created.credentialA,
                "owner",
                "access",
            );
            const primary = value.clientA.buildSuccessorRecord(
                created.initial,
                content(value, "title: primary"),
            );
            const fork = value.clientA.buildSuccessorRecord(
                created.initial,
                content(value, "title: fork"),
            );
            const accepted = await value.service.replaceRecord({
                replacesVersion: created.initial.canonicalVersion,
                expectedRevisionHash: created.initial.revisionHash,
                record: primary,
                token: ownerToken.bytes,
            });
            value.clientA.acceptRecord(accepted, {
                session: value.sessionAB,
                roles: value.rolesAB,
            });
            expect(() =>
                value.clientA.acceptRecord(stored(fork, accepted), {
                    session: value.sessionAB,
                    roles: value.rolesAB,
                }),
            ).toThrow("fork detected");
            expect(() =>
                value.clientA.acceptRecord(created.initial, {
                    session: value.sessionAB,
                    roles: value.rolesAB,
                }),
            ).toThrow("rollback detected");
            await expect(
                value.service.replaceRecord({
                    replacesVersion: created.initial.canonicalVersion,
                    expectedRevisionHash: created.initial.revisionHash,
                    record: fork,
                    token: ownerToken.bytes,
                }),
            ).rejects.toThrow("does not extend the expected version");
        } finally {
            value.close();
        }
    });
});
