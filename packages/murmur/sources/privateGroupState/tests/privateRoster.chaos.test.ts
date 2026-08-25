import {
    PrivateGroupStateService,
    SqlitePrivateGroupStateStore,
    encodePrivateGroupStateRecord as encodeServiceRecord,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import { SeededRandom } from "../../chaos/index.js";
import { deriveCredentialIssuer } from "../../privateGroups/index.js";
import {
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import {
    PrivateGroupStateClient,
    createPrivateGroupCredentialAuthority,
    privateGroupStateRecordHash,
    type PrivateGroupAccessToken,
    type PrivateGroupAccountCredential,
    type PrivateGroupAccountRole,
    type PrivateGroupPresentationChallenge,
    type PrivateGroupRecordContent,
    type PrivateGroupRole,
    type PrivateGroupStateRecord,
    type PrivateGroupStateTransport,
    type StoredPrivateGroupStateRecord,
} from "../index.js";

const START = 1_800_000_000_000;
const CREDENTIAL_LIFETIME = 5 * 60_000;
const CHALLENGE_LIFETIME = 30_000;
const TOKEN_LIFETIME = 60_000;
const CAMPAIGN_SEED = 0x524f_4c45;

interface ServiceTraceEntry {
    readonly operation: string;
    readonly revision?: number;
    readonly digest?: string;
}

interface PrivateFixture {
    readonly clock: { value: number };
    readonly groupSecret: Uint8Array;
    readonly accounts: readonly Uint8Array[];
    readonly store: SqlitePrivateGroupStateStore;
    readonly service: PrivateGroupStateService;
    readonly transport: TracingPrivateTransport;
    readonly clients: PrivateGroupStateClient[];
    readonly clientA: PrivateGroupStateClient;
    readonly clientB: PrivateGroupStateClient;
    readonly clientC: PrivateGroupStateClient;
    newClient(
        accountIndex: number,
        trustedTip?: { readonly revision: number; readonly revisionHash: Uint8Array },
    ): PrivateGroupStateClient;
    close(): void;
}

interface Baseline {
    readonly content: PrivateGroupRecordContent;
    readonly credentialA: PrivateGroupAccountCredential;
    readonly credentialB: PrivateGroupAccountCredential;
    readonly credentialC: PrivateGroupAccountCredential;
    readonly ownerToken: PrivateGroupAccessToken;
    readonly adminToken: PrivateGroupAccessToken;
    readonly memberToken: PrivateGroupAccessToken;
    readonly current: StoredPrivateGroupStateRecord;
}

class TracingPrivateTransport implements PrivateGroupStateTransport {
    readonly #delegate: PrivateGroupStateService;
    readonly trace: ServiceTraceEntry[] = [];
    loseNextReplaceResponse = false;

    constructor(delegate: PrivateGroupStateService) {
        this.#delegate = delegate;
    }

    get credentialIssuerPublicParameters(): Uint8Array {
        return this.#delegate.credentialIssuerPublicParameters;
    }

    credentialIssuanceContext(authenticationContext: Uint8Array): Uint8Array {
        this.trace.push({ operation: "credential-context" });
        return this.#delegate.credentialIssuanceContext(authenticationContext);
    }

    async issueCredential(options: {
        readonly authenticatedAccountIdentifier: Uint8Array;
        readonly request: Uint8Array;
        readonly authenticationContext: Uint8Array;
    }): Promise<Uint8Array> {
        this.trace.push({ operation: "issue-credential" });
        return this.#delegate.issueCredential(options);
    }

    async createPresentationChallenge(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly entry: Uint8Array;
        readonly role: PrivateGroupRole;
        readonly operation: "create" | "access";
    }): Promise<PrivateGroupPresentationChallenge> {
        this.trace.push({ operation: `challenge-${options.operation}` });
        return this.#delegate.createPresentationChallenge(options);
    }

    async authenticatePresentation(options: {
        readonly challenge: PrivateGroupPresentationChallenge;
        readonly publicParameters: Uint8Array;
        readonly presentation: Uint8Array;
    }): Promise<PrivateGroupAccessToken> {
        this.trace.push({ operation: "authenticate-presentation" });
        return this.#delegate.authenticatePresentation(options);
    }

    async createRecord(options: {
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        this.#record("create", options.record);
        return this.#delegate.createRecord(options);
    }

    async readRecord(options: {
        readonly opaqueGroupId: Uint8Array;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        this.trace.push({ operation: "read" });
        return this.#delegate.readRecord(options);
    }

    async replaceRecord(options: {
        readonly expectedRevision: number;
        readonly expectedRevisionHash: Uint8Array;
        readonly record: PrivateGroupStateRecord;
        readonly token: Uint8Array;
    }): Promise<StoredPrivateGroupStateRecord> {
        this.#record("replace", options.record);
        const result = await this.#delegate.replaceRecord(options);
        if (this.loseNextReplaceResponse) {
            this.loseNextReplaceResponse = false;
            throw new Error("Injected lost private-state response");
        }
        return result;
    }

    #record(operation: string, record: PrivateGroupStateRecord): void {
        this.trace.push({
            operation,
            revision: record.revision,
            digest: encodeBase64Url(privateGroupStateRecordHash(record)),
        });
    }
}

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

function privateFixture(): PrivateFixture {
    const clock = { value: START };
    const groupSecret = bytes(101);
    const accounts = [bytes(11), bytes(12), bytes(13), bytes(14), bytes(15)] as const;
    const issuer = deriveCredentialIssuer(bytes(91));
    const store = new SqlitePrivateGroupStateStore(":memory:");
    const service = new PrivateGroupStateService({
        store,
        credentialAuthority: createPrivateGroupCredentialAuthority(issuer),
        tokenSecret: bytes(201),
        now: () => clock.value,
        credentialLifetimeMilliseconds: CREDENTIAL_LIFETIME,
        challengeLifetimeMilliseconds: CHALLENGE_LIFETIME,
        tokenLifetimeMilliseconds: TOKEN_LIFETIME,
    });
    const transport = new TracingPrivateTransport(service);
    const clients: PrivateGroupStateClient[] = [];
    const newClient = (
        accountIndex: number,
        trustedTip?: { readonly revision: number; readonly revisionHash: Uint8Array },
    ): PrivateGroupStateClient => {
        const client = new PrivateGroupStateClient({
            accountIdentifier: accounts[accountIndex]!,
            groupMasterSecret: groupSecret,
            transport,
            now: () => clock.value,
            ...(trustedTip === undefined ? {} : { trustedTip }),
        });
        clients.push(client);
        return client;
    };
    const clientA = newClient(0);
    const clientB = newClient(1);
    const clientC = newClient(2);
    return {
        clock,
        groupSecret,
        accounts,
        store,
        service,
        transport,
        clients,
        clientA,
        clientB,
        clientC,
        newClient,
        close: (): void => {
            for (const client of clients) client.close();
            service.close();
            zeroBytes(groupSecret);
        },
    };
}

function content(
    fixture: PrivateFixture,
    assignments: readonly PrivateGroupAccountRole[],
    attributes: string,
    policies: { readonly adminsAssignAdmins: boolean; readonly anyoneCanAddMembers: boolean } = {
        adminsAssignAdmins: false,
        anyoneCanAddMembers: false,
    },
): PrivateGroupRecordContent {
    const owner = assignments.find((assignment) => assignment.role === "owner");
    if (owner === undefined) throw new Error("Private chaos content requires one owner");
    return {
        attributes: utf8Encode(attributes),
        session: {
            id: bytes(151),
            status: "active",
            descriptor: utf8Encode("private roster chaos"),
            members: assignments.map((assignment) => assignment.accountIdentifier),
            owner: owner.accountIdentifier,
            admins: assignments
                .filter((assignment) => assignment.role !== "member")
                .map((assignment) => assignment.accountIdentifier),
            policies,
        },
        roles: assignments,
    };
}

function baselineAssignments(fixture: PrivateFixture): readonly PrivateGroupAccountRole[] {
    return [
        { accountIdentifier: fixture.accounts[0]!, role: "owner" },
        { accountIdentifier: fixture.accounts[1]!, role: "administrator" },
        { accountIdentifier: fixture.accounts[2]!, role: "member" },
    ];
}

async function createBaseline(fixture: PrivateFixture): Promise<Baseline> {
    const baselineContent = content(fixture, baselineAssignments(fixture), "revision 1");
    const credentialA = await fixture.clientA.obtainCredential(utf8Encode("auth/A"));
    const accepted = await fixture.clientA.createGroup(credentialA, baselineContent);
    const credentialB = await fixture.clientB.obtainCredential(utf8Encode("auth/B"));
    const credentialC = await fixture.clientC.obtainCredential(utf8Encode("auth/C"));
    const ownerToken = await fixture.clientA.authorize(credentialA, "owner", "access");
    const adminToken = await fixture.clientB.authorize(credentialB, "administrator", "access");
    const memberToken = await fixture.clientC.authorize(credentialC, "member", "access");
    await fixture.clientB.readGroup(adminToken, baselineContent);
    await fixture.clientC.readGroup(memberToken, baselineContent);
    return {
        content: baselineContent,
        credentialA,
        credentialB,
        credentialC,
        ownerToken,
        adminToken,
        memberToken,
        current: accepted.record,
    };
}

function stored(record: PrivateGroupStateRecord): StoredPrivateGroupStateRecord {
    return { record, revisionHash: privateGroupStateRecordHash(record) };
}

function replacementOptions(
    current: StoredPrivateGroupStateRecord,
    record: PrivateGroupStateRecord,
    token: PrivateGroupAccessToken,
): {
    readonly expectedRevision: number;
    readonly expectedRevisionHash: Uint8Array;
    readonly record: PrivateGroupStateRecord;
    readonly token: Uint8Array;
} {
    return {
        expectedRevision: current.record.revision,
        expectedRevisionHash: current.revisionHash,
        record,
        token: token.bytes,
    };
}

function expectOpaqueRecord(fixture: PrivateFixture, record: PrivateGroupStateRecord): void {
    const raw = encodeServiceRecord(record);
    const trace = JSON.stringify(fixture.transport.trace);
    for (const account of fixture.accounts) {
        expect(containsSequence(raw, account)).toBe(false);
        expect(containsSequence(raw, utf8Encode(encodeBase64Url(account)))).toBe(false);
        expect(trace).not.toContain(encodeBase64Url(account));
    }
}

describe("private canonical roster chaos", () => {
    test("ROSTER-01 competing revisions retain only the CAS winner and MLS-bound roster", async () => {
        const fixture = privateFixture();
        try {
            const baseline = await createBaseline(fixture);
            const winnerContent = content(
                fixture,
                [
                    ...baselineAssignments(fixture),
                    { accountIdentifier: fixture.accounts[3]!, role: "member" },
                ],
                "winner adds D",
            );
            const loserContent = content(
                fixture,
                [
                    ...baselineAssignments(fixture),
                    { accountIdentifier: fixture.accounts[4]!, role: "member" },
                ],
                "loser adds E",
            );
            const winner = fixture.clientA.buildSuccessorRecord(baseline.current, winnerContent);
            const loser = fixture.clientA.buildSuccessorRecord(baseline.current, loserContent);
            const accepted = await fixture.transport.replaceRecord(
                replacementOptions(baseline.current, winner, baseline.ownerToken),
            );
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(baseline.current, loser, baseline.ownerToken),
                ),
            ).rejects.toThrow();
            const opened = fixture.clientA.acceptRecord(accepted, winnerContent);
            expect(utf8Decode(opened.attributes)).toBe("winner adds D");
            expect(() => fixture.clientA.acceptRecord(stored(loser), winnerContent)).toThrow();
            const canonical = fixture.store.read(fixture.clientA.opaqueGroupId)!;
            expect(canonical.record.revision).toBe(2);
            expect(canonical.revisionHash).toEqual(accepted.revisionHash);
            expectOpaqueRecord(fixture, canonical.record);
        } finally {
            fixture.close();
        }
    });

    test("ROSTER-02 a lost accepted response reconciles to one canonical digest", async () => {
        const fixture = privateFixture();
        try {
            const baseline = await createBaseline(fixture);
            const nextContent = content(
                fixture,
                baselineAssignments(fixture),
                "lost response revision",
                { adminsAssignAdmins: true, anyoneCanAddMembers: false },
            );
            const next = fixture.clientA.buildSuccessorRecord(baseline.current, nextContent);
            fixture.transport.loseNextReplaceResponse = true;
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(baseline.current, next, baseline.ownerToken),
                ),
            ).rejects.toThrow("lost private-state response");
            const canonical = fixture.store.read(fixture.clientA.opaqueGroupId)!;
            expect(canonical.record.revision).toBe(2);
            expect(canonical.revisionHash).toEqual(privateGroupStateRecordHash(next));
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(baseline.current, next, baseline.ownerToken),
                ),
            ).rejects.toThrow();
            const reconciled = fixture.clientA.acceptRecord(canonical, nextContent);
            expect(reconciled.record.revisionHash).toEqual(canonical.revisionHash);
            expect(fixture.store.read(fixture.clientA.opaqueGroupId)?.record.revision).toBe(2);
        } finally {
            fixture.close();
        }
    });

    test("ROSTER-03 stale, skipped, and wrong-parent revisions cannot mutate the tip", async () => {
        const fixture = privateFixture();
        try {
            const baseline = await createBaseline(fixture);
            const secondContent = content(fixture, baselineAssignments(fixture), "revision 2");
            const secondRecord = fixture.clientA.buildSuccessorRecord(
                baseline.current,
                secondContent,
            );
            const second = await fixture.transport.replaceRecord(
                replacementOptions(baseline.current, secondRecord, baseline.ownerToken),
            );
            fixture.clientA.acceptRecord(second, secondContent);
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(baseline.current, secondRecord, baseline.ownerToken),
                ),
            ).rejects.toThrow();

            const thirdContent = content(fixture, baselineAssignments(fixture), "revision 3");
            const thirdRecord = fixture.clientA.buildSuccessorRecord(second, thirdContent);
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(
                        second,
                        { ...thirdRecord, revision: thirdRecord.revision + 1 },
                        baseline.ownerToken,
                    ),
                ),
            ).rejects.toThrow();
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(
                        second,
                        { ...thirdRecord, previousRevisionHash: bytes(250) },
                        baseline.ownerToken,
                    ),
                ),
            ).rejects.toThrow();
            expect(fixture.store.read(fixture.clientA.opaqueGroupId)?.record.revision).toBe(2);
            const third = await fixture.transport.replaceRecord(
                replacementOptions(second, thirdRecord, baseline.ownerToken),
            );
            fixture.clientA.acceptRecord(third, thirdContent);
            expect(third.record.revision).toBe(3);
        } finally {
            fixture.close();
        }
    });

    test("ROSTER-04 owner/admin tokens mutate while members and removed admins cannot", async () => {
        const fixture = privateFixture();
        try {
            const baseline = await createBaseline(fixture);
            const secondContent = content(fixture, baselineAssignments(fixture), "admin mutation", {
                adminsAssignAdmins: true,
                anyoneCanAddMembers: false,
            });
            const secondRecord = fixture.clientA.buildSuccessorRecord(
                baseline.current,
                secondContent,
            );
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(baseline.current, secondRecord, baseline.memberToken),
                ),
            ).rejects.toThrow();
            const second = await fixture.transport.replaceRecord(
                replacementOptions(baseline.current, secondRecord, baseline.adminToken),
            );
            fixture.clientA.acceptRecord(second, secondContent);

            const demotedAssignments: readonly PrivateGroupAccountRole[] = [
                { accountIdentifier: fixture.accounts[0]!, role: "owner" },
                { accountIdentifier: fixture.accounts[1]!, role: "member" },
                { accountIdentifier: fixture.accounts[2]!, role: "member" },
            ];
            const thirdContent = content(fixture, demotedAssignments, "admin removed");
            const thirdRecord = fixture.clientA.buildSuccessorRecord(second, thirdContent);
            const third = await fixture.transport.replaceRecord(
                replacementOptions(second, thirdRecord, baseline.ownerToken),
            );
            fixture.clientA.acceptRecord(third, thirdContent);
            const fourthRecord = fixture.clientA.buildSuccessorRecord(
                third,
                content(fixture, demotedAssignments, "removed admin attack"),
            );
            await expect(
                fixture.transport.replaceRecord(
                    replacementOptions(third, fourthRecord, baseline.adminToken),
                ),
            ).rejects.toThrow();
            expect(fixture.store.read(fixture.clientA.opaqueGroupId)?.record.revision).toBe(3);
        } finally {
            fixture.close();
        }
    });

    test("ROSTER-05 credential, challenge, token, replay, and binding boundaries fail closed", async () => {
        const fixture = privateFixture();
        try {
            const baseline = await createBaseline(fixture);
            const parameters = fixture.clientA.buildInitialRecord(
                baseline.content,
            ).publicParameters;

            fixture.clock.value = baseline.credentialA.expiresAt - 2;
            const credentialChallenge = await fixture.transport.createPresentationChallenge({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                entry: fixture.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "access",
            });
            const credentialPresentation = fixture.clientA.createPresentation(
                baseline.credentialA,
                credentialChallenge,
            );
            fixture.clock.value = baseline.credentialA.expiresAt - 1;
            await fixture.transport.authenticatePresentation({
                challenge: credentialChallenge,
                publicParameters: parameters,
                presentation: credentialPresentation,
            });
            const exactCredentialChallenge = await fixture.transport.createPresentationChallenge({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                entry: fixture.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "access",
            });
            fixture.clock.value = baseline.credentialA.expiresAt;
            expect(() =>
                fixture.clientA.createPresentation(baseline.credentialA, exactCredentialChallenge),
            ).toThrow();
            fixture.clock.value += 1;
            expect(() =>
                fixture.clientA.createPresentation(baseline.credentialA, exactCredentialChallenge),
            ).toThrow();

            const freshCredential = await fixture.clientA.obtainCredential(utf8Encode("fresh"));
            const validChallenge = await fixture.transport.createPresentationChallenge({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                entry: fixture.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "access",
            });
            const validPresentation = fixture.clientA.createPresentation(
                freshCredential,
                validChallenge,
            );
            fixture.clock.value = validChallenge.expiresAt - 1;
            await fixture.transport.authenticatePresentation({
                challenge: validChallenge,
                publicParameters: parameters,
                presentation: validPresentation,
            });
            await expect(
                fixture.transport.authenticatePresentation({
                    challenge: validChallenge,
                    publicParameters: parameters,
                    presentation: validPresentation,
                }),
            ).rejects.toThrow();

            const exactChallenge = await fixture.transport.createPresentationChallenge({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                entry: fixture.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "access",
            });
            const exactPresentation = fixture.clientA.createPresentation(
                freshCredential,
                exactChallenge,
            );
            fixture.clock.value = exactChallenge.expiresAt;
            await expect(
                fixture.transport.authenticatePresentation({
                    challenge: exactChallenge,
                    publicParameters: parameters,
                    presentation: exactPresentation,
                }),
            ).rejects.toThrow();

            const plusChallenge = await fixture.transport.createPresentationChallenge({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                entry: fixture.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "access",
            });
            const plusPresentation = fixture.clientA.createPresentation(
                freshCredential,
                plusChallenge,
            );
            fixture.clock.value = plusChallenge.expiresAt + 1;
            await expect(
                fixture.transport.authenticatePresentation({
                    challenge: plusChallenge,
                    publicParameters: parameters,
                    presentation: plusPresentation,
                }),
            ).rejects.toThrow();

            const mutatedChallenge = await fixture.transport.createPresentationChallenge({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                entry: fixture.clientA.ownEncryptedEntry,
                role: "owner",
                operation: "access",
            });
            const mutatedPresentation = fixture.clientA.createPresentation(
                freshCredential,
                mutatedChallenge,
            );
            mutatedPresentation[0] = mutatedPresentation[0]! ^ 1;
            await expect(
                fixture.transport.authenticatePresentation({
                    challenge: mutatedChallenge,
                    publicParameters: parameters,
                    presentation: mutatedPresentation,
                }),
            ).rejects.toThrow();

            const token = await fixture.clientA.authorize(freshCredential, "owner", "access");
            fixture.clock.value = token.expiresAt - 1;
            await fixture.transport.readRecord({
                opaqueGroupId: fixture.clientA.opaqueGroupId,
                token: token.bytes,
            });
            await expect(
                fixture.transport.readRecord({ opaqueGroupId: bytes(99), token: token.bytes }),
            ).rejects.toThrow();
            fixture.clock.value = token.expiresAt;
            await expect(
                fixture.transport.readRecord({
                    opaqueGroupId: fixture.clientA.opaqueGroupId,
                    token: token.bytes,
                }),
            ).rejects.toThrow();
            fixture.clock.value += 1;
            await expect(
                fixture.transport.readRecord({
                    opaqueGroupId: fixture.clientA.opaqueGroupId,
                    token: token.bytes,
                }),
            ).rejects.toThrow();
            expect(fixture.store.read(fixture.clientA.opaqueGroupId)?.record.revision).toBe(1);
        } finally {
            fixture.close();
        }
    });

    test("ROSTER-06 crash cuts reconcile to wholly old or matching MLS/service state", async () => {
        for (const cut of [
            "before-persist",
            "after-service",
            "after-mls",
            "before-completion",
        ] as const) {
            const fixture = privateFixture();
            try {
                const baseline = await createBaseline(fixture);
                const nextContent = content(
                    fixture,
                    baselineAssignments(fixture),
                    `crash cut ${cut}`,
                    { adminsAssignAdmins: cut === "after-mls", anyoneCanAddMembers: false },
                );
                const nextRecord = fixture.clientA.buildSuccessorRecord(
                    baseline.current,
                    nextContent,
                );
                if (cut !== "before-persist") {
                    if (cut === "after-service") fixture.transport.loseNextReplaceResponse = true;
                    await fixture.transport
                        .replaceRecord(
                            replacementOptions(baseline.current, nextRecord, baseline.ownerToken),
                        )
                        .catch((error: unknown) => {
                            if (cut !== "after-service") throw error;
                        });
                }
                const canonical = fixture.store.read(fixture.clientA.opaqueGroupId)!;
                expect(canonical.record.revision).toBe(cut === "before-persist" ? 1 : 2);
                if (canonical.record.revision === 2) {
                    const reopened = fixture.newClient(0, {
                        revision: baseline.current.record.revision,
                        revisionHash: baseline.current.revisionHash,
                    });
                    const accepted = reopened.acceptRecord(canonical, nextContent);
                    expect(utf8Decode(accepted.attributes)).toBe(`crash cut ${cut}`);
                } else {
                    expect(canonical.revisionHash).toEqual(baseline.current.revisionHash);
                }
            } finally {
                fixture.close();
            }
        }
    });

    test("ROSTER-07 seeded 25-revision race converges and trace contains no UID", async () => {
        const fixture = privateFixture();
        try {
            const baseline = await createBaseline(fixture);
            const random = new SeededRandom(CAMPAIGN_SEED);
            let assignments = [...baselineAssignments(fixture)];
            let policies = {
                adminsAssignAdmins: false,
                anyoneCanAddMembers: false,
            };
            let current = baseline.current;
            let owner = fixture.clientA;
            const crashRevisions = new Set([6, 11, 16, 21, 26]);
            const lostResponseRevisions = new Set(
                Array.from({ length: 10 }, (_, index) => index + 2),
            );
            let finalContent = baseline.content;
            for (let revision = 2; revision <= 26; revision += 1) {
                const account = fixture.accounts[random.integer(1, fixture.accounts.length)]!;
                const existing = assignments.findIndex((entry) =>
                    equalBytes(entry.accountIdentifier, account),
                );
                const operation = random.integer(0, 4);
                if (operation === 0 && existing < 0) {
                    assignments.push({ accountIdentifier: account, role: "member" });
                } else if (operation === 1 && existing >= 0) {
                    assignments.splice(existing, 1);
                } else if (operation === 2 && existing >= 0) {
                    const prior = assignments[existing]!;
                    assignments[existing] = {
                        accountIdentifier: prior.accountIdentifier,
                        role: prior.role === "administrator" ? "member" : "administrator",
                    };
                } else {
                    policies = {
                        adminsAssignAdmins: !policies.adminsAssignAdmins,
                        anyoneCanAddMembers:
                            operation === 3
                                ? !policies.anyoneCanAddMembers
                                : policies.anyoneCanAddMembers,
                    };
                }
                finalContent = content(
                    fixture,
                    assignments,
                    `campaign revision ${revision}`,
                    policies,
                );
                const record = owner.buildSuccessorRecord(current, finalContent);
                fixture.transport.loseNextReplaceResponse = lostResponseRevisions.has(revision);
                let accepted: StoredPrivateGroupStateRecord;
                try {
                    accepted = await fixture.transport.replaceRecord(
                        replacementOptions(current, record, baseline.ownerToken),
                    );
                } catch (error: unknown) {
                    if (!lostResponseRevisions.has(revision)) throw error;
                    accepted = fixture.store.read(owner.opaqueGroupId)!;
                }
                owner.acceptRecord(accepted, finalContent);
                current = accepted;
                expect(current.record.revision).toBe(revision);
                expectOpaqueRecord(fixture, current.record);
                if (crashRevisions.has(revision)) {
                    owner.close();
                    owner = fixture.newClient(0, {
                        revision: current.record.revision,
                        revisionHash: current.revisionHash,
                    });
                }
            }

            expect(current.record.revision).toBe(26);
            for (const assignment of assignments) {
                const accountIndex = fixture.accounts.findIndex((account) =>
                    equalBytes(account, assignment.accountIdentifier),
                );
                const reader = fixture.newClient(accountIndex);
                const credential = await reader.obtainCredential(
                    utf8Encode(`campaign reader ${accountIndex}`),
                );
                const token = await reader.authorize(credential, assignment.role, "access");
                const accepted = await reader.readGroup(token, finalContent);
                expect(accepted.record.revisionHash).toEqual(current.revisionHash);
                expect(utf8Decode(accepted.attributes)).toBe("campaign revision 26");
            }
            const traceJson = JSON.stringify(fixture.transport.trace);
            for (const account of fixture.accounts) {
                expect(traceJson).not.toContain(encodeBase64Url(account));
            }
            expect(
                fixture.transport.trace.filter((entry) => entry.operation === "replace"),
            ).toHaveLength(25);
        } finally {
            fixture.close();
        }
    }, 120_000);
});
