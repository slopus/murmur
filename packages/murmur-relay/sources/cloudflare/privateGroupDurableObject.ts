import {
    createPrivateGroupStateFetchHandler,
    createPrivateGroupStateServiceFromSecret,
} from "../privateGroupState/index.js";
import type {
    PrivateGroupPresentationChallenge,
    PrivateGroupRole,
    PrivateGroupStateLimits,
    PrivateGroupStateRecord,
    PrivateGroupStateStore,
    StoredPrivateGroupStateRecord,
} from "../privateGroupState/types.js";
import { decodeBase64Url, encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { nextUuidV7 } from "../utils/uuidV7.js";
import type {
    DurableObjectStateLike,
    DurableObjectTransactionLike,
    MurmurCloudflareEnvironment,
} from "./types.js";
import { parseTokenSecret } from "./impl/cloudflareCodec.js";

const PRIVATE_GROUP_PREFIX = "/v1/private-groups/";
const GROUP_PATHS = new Set([
    "/v1/private-groups/challenges",
    "/v1/private-groups/presentations",
    "/v1/private-groups/records/create",
    "/v1/private-groups/records/read",
    "/v1/private-groups/records/replace",
]);
const GROUP_ID_KEY = "private-group:id";
const CURRENT_RECORD_KEY = "private-group:record";
const MEMBER_PREFIX = "private-group:member:";
const CHALLENGE_PREFIX = "private-group:challenge:";

function json(body: unknown, status: number): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

function parseCanonicalBytes(value: string | null, length: number): Uint8Array {
    if (value === null) throw new Error("Missing canonical bytes");
    const bytes = decodeBase64Url(value, length);
    if (encodeBase64Url(bytes) !== value) throw new Error("Non-canonical bytes");
    return bytes;
}

function privateGroupSecret(environment: MurmurCloudflareEnvironment): Uint8Array {
    let secret: Uint8Array | undefined;
    let relaySecret: Uint8Array | undefined;
    try {
        secret = parseCanonicalBytes(environment.MURMUR_PRIVATE_GROUP_SECRET, 32);
        relaySecret = parseTokenSecret(environment.MURMUR_RELAY_TOKEN_SECRET);
        if (equalBytes(secret, relaySecret)) {
            throw new Error("Private-group and relay-ticket secrets must differ");
        }
        return secret;
    } catch {
        secret?.fill(0);
        throw new Error(
            "Cloudflare private-group and relay-ticket secrets must be canonical and distinct",
        );
    } finally {
        relaySecret?.fill(0);
    }
}

function cloneRecord(record: PrivateGroupStateRecord): PrivateGroupStateRecord {
    return {
        version: 1,
        opaqueGroupId: record.opaqueGroupId.slice(),
        publicParameters: record.publicParameters.slice(),
        revision: record.revision,
        previousRevisionHash: record.previousRevisionHash?.slice() ?? null,
        members: record.members.map((member) => ({
            entry: member.entry.slice(),
            role: member.role,
        })),
        sealedState: record.sealedState.slice(),
        revisionAuthenticator: record.revisionAuthenticator.slice(),
    };
}

function cloneStored(record: StoredPrivateGroupStateRecord): StoredPrivateGroupStateRecord {
    return {
        record: cloneRecord(record.record),
        revisionHash: record.revisionHash.slice(),
        canonicalVersion: record.canonicalVersion,
        replacesVersion: record.replacesVersion,
        commitEventId: record.commitEventId,
    };
}

function cloneChallenge(
    challenge: PrivateGroupPresentationChallenge,
): PrivateGroupPresentationChallenge {
    return {
        opaqueGroupId: challenge.opaqueGroupId.slice(),
        entry: challenge.entry.slice(),
        role: challenge.role,
        operation: challenge.operation,
        replayNonce: challenge.replayNonce.slice(),
        context: challenge.context.slice(),
        expiresAt: challenge.expiresAt,
    };
}

function memberKey(entry: Uint8Array): string {
    return `${MEMBER_PREFIX}${encodeBase64Url(entry)}`;
}

function challengeKey(replayNonce: Uint8Array): string {
    return `${CHALLENGE_PREFIX}${encodeBase64Url(replayNonce)}`;
}

async function replaceMembers(
    transaction: DurableObjectTransactionLike,
    record: PrivateGroupStateRecord,
): Promise<void> {
    const previous = await transaction.list<PrivateGroupRole>({ prefix: MEMBER_PREFIX });
    if (previous.size > 0) await transaction.delete([...previous.keys()]);
    for (const member of record.members) {
        await transaction.put(memberKey(member.entry), member.role);
    }
}

/** Persistent private-group state pinned to one opaque group Durable Object. */
export class CloudflarePrivateGroupStateStore implements PrivateGroupStateStore {
    readonly #state: DurableObjectStateLike;
    readonly #opaqueGroupId: Uint8Array;

    constructor(state: DurableObjectStateLike, opaqueGroupId: Uint8Array) {
        this.#state = state;
        this.#opaqueGroupId = opaqueGroupId.slice();
    }

    /** Permanently bind fresh object storage to the group selected by Worker ingress. */
    async pin(): Promise<void> {
        const encodedGroupId = encodeBase64Url(this.#opaqueGroupId);
        await this.#state.storage.transaction(async (transaction) => {
            const existing = await transaction.get<string>(GROUP_ID_KEY);
            if (existing !== undefined && existing !== encodedGroupId) {
                throw new Error("Private-group Durable Object is pinned to another group");
            }
            if (existing === undefined) await transaction.put(GROUP_ID_KEY, encodedGroupId);
        });
    }

    async create(
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        limits: PrivateGroupStateLimits,
        now: number,
    ): Promise<StoredPrivateGroupStateRecord> {
        this.#assertGroup(record.opaqueGroupId);
        if (rawRecord.length < 1 || rawRecord.length > limits.maximumRecordBytes) {
            throw new Error("Private-group record exceeds byte limit");
        }
        return await this.#state.storage.transaction(async (transaction) => {
            const existing =
                await transaction.get<StoredPrivateGroupStateRecord>(CURRENT_RECORD_KEY);
            if (existing !== undefined) {
                if (!equalBytes(existing.revisionHash, revisionHash)) {
                    throw new Error("Private group already exists with different state");
                }
                return cloneStored(existing);
            }
            const stored: StoredPrivateGroupStateRecord = {
                record: cloneRecord(record),
                revisionHash: revisionHash.slice(),
                canonicalVersion: nextUuidV7(now, null),
                replacesVersion: null,
                commitEventId: null,
            };
            await transaction.put(CURRENT_RECORD_KEY, stored);
            await replaceMembers(transaction, record);
            return cloneStored(stored);
        });
    }

    async replace(
        replacesVersion: string,
        expectedRevisionHash: Uint8Array,
        record: PrivateGroupStateRecord,
        revisionHash: Uint8Array,
        rawRecord: Uint8Array,
        limits: PrivateGroupStateLimits,
        now: number,
    ): Promise<StoredPrivateGroupStateRecord> {
        this.#assertGroup(record.opaqueGroupId);
        if (rawRecord.length < 1 || rawRecord.length > limits.maximumRecordBytes) {
            throw new Error("Private-group record exceeds byte limit");
        }
        return await this.#state.storage.transaction(async (transaction) => {
            const current =
                await transaction.get<StoredPrivateGroupStateRecord>(CURRENT_RECORD_KEY);
            if (current === undefined) throw new Error("Unknown private group");
            if (
                current.replacesVersion === replacesVersion &&
                equalBytes(current.revisionHash, revisionHash)
            ) {
                return cloneStored(current);
            }
            if (
                current.canonicalVersion !== replacesVersion ||
                current.record.revision + 1 !== record.revision ||
                !equalBytes(current.revisionHash, expectedRevisionHash)
            ) {
                throw new Error("Private-group canonical version conflict");
            }
            const stored: StoredPrivateGroupStateRecord = {
                record: cloneRecord(record),
                revisionHash: revisionHash.slice(),
                canonicalVersion: nextUuidV7(now, current.canonicalVersion),
                replacesVersion,
                commitEventId: null,
            };
            await transaction.put(CURRENT_RECORD_KEY, stored);
            await replaceMembers(transaction, record);
            return cloneStored(stored);
        });
    }

    async read(opaqueGroupId: Uint8Array): Promise<StoredPrivateGroupStateRecord | undefined> {
        this.#assertGroup(opaqueGroupId);
        const stored =
            await this.#state.storage.get<StoredPrivateGroupStateRecord>(CURRENT_RECORD_KEY);
        return stored === undefined ? undefined : cloneStored(stored);
    }

    async hasMember(
        opaqueGroupId: Uint8Array,
        entry: Uint8Array,
        role: PrivateGroupRole,
    ): Promise<boolean> {
        this.#assertGroup(opaqueGroupId);
        return (await this.#state.storage.get<PrivateGroupRole>(memberKey(entry))) === role;
    }

    async storeChallenge(
        challenge: PrivateGroupPresentationChallenge,
        maximumPendingChallenges: number,
        now: number,
    ): Promise<void> {
        this.#assertGroup(challenge.opaqueGroupId);
        await this.#state.storage.transaction(async (transaction) => {
            const challenges = await transaction.list<PrivateGroupPresentationChallenge>({
                prefix: CHALLENGE_PREFIX,
            });
            const expired = [...challenges.entries()]
                .filter(([, stored]) => stored.expiresAt <= now)
                .map(([key]) => key);
            if (expired.length > 0) await transaction.delete(expired);
            if (challenges.size - expired.length >= maximumPendingChallenges) {
                throw new Error("Private-group presentation challenge quota exceeded");
            }
            const key = challengeKey(challenge.replayNonce);
            if (challenges.has(key) && !expired.includes(key)) {
                throw new Error("Duplicate private-group presentation challenge");
            }
            await transaction.put(key, cloneChallenge(challenge));
        });
    }

    async consumeChallenge(
        replayNonce: Uint8Array,
        now: number,
    ): Promise<PrivateGroupPresentationChallenge | undefined> {
        return await this.#state.storage.transaction(async (transaction) => {
            const key = challengeKey(replayNonce);
            const challenge = await transaction.get<PrivateGroupPresentationChallenge>(key);
            if (challenge === undefined) return undefined;
            await transaction.delete(key);
            if (challenge.expiresAt <= now) return undefined;
            this.#assertGroup(challenge.opaqueGroupId);
            return cloneChallenge(challenge);
        });
    }

    close(): void {
        // Durable Object storage is owned by the runtime and persists after each request.
    }

    #assertGroup(opaqueGroupId: Uint8Array): void {
        if (!equalBytes(opaqueGroupId, this.#opaqueGroupId)) {
            throw new Error("Private-group request was routed to the wrong Durable Object");
        }
    }
}

const ingressStore: PrivateGroupStateStore = {
    create: () => {
        throw new Error("Private-group records require a group Durable Object");
    },
    replace: () => {
        throw new Error("Private-group records require a group Durable Object");
    },
    read: () => {
        throw new Error("Private-group records require a group Durable Object");
    },
    hasMember: () => {
        throw new Error("Private-group records require a group Durable Object");
    },
    storeChallenge: () => {
        throw new Error("Private-group challenges require a group Durable Object");
    },
    consumeChallenge: () => {
        throw new Error("Private-group challenges require a group Durable Object");
    },
    close: () => undefined,
};

async function handleWithStore(
    request: Request,
    environment: MurmurCloudflareEnvironment,
    store: PrivateGroupStateStore,
): Promise<Response> {
    const secret = privateGroupSecret(environment);
    try {
        const service = createPrivateGroupStateServiceFromSecret({ store, secret });
        try {
            return await createPrivateGroupStateFetchHandler(service)(request);
        } finally {
            service.close();
        }
    } finally {
        secret.fill(0);
    }
}

/** One opaque group's persistent canonical state and presentation challenges. */
export class MurmurPrivateGroupDurableObject {
    readonly #state: DurableObjectStateLike;
    readonly #environment: MurmurCloudflareEnvironment;

    constructor(state: DurableObjectStateLike, environment: MurmurCloudflareEnvironment) {
        this.#state = state;
        this.#environment = environment;
    }

    /** Serve only requests carrying the exact group ID selected at public ingress. */
    async fetch(request: Request): Promise<Response> {
        let store: CloudflarePrivateGroupStateStore;
        try {
            const opaqueGroupId = parseCanonicalBytes(
                request.headers.get("x-murmur-private-group"),
                32,
            );
            store = new CloudflarePrivateGroupStateStore(this.#state, opaqueGroupId);
            await store.pin();
        } catch {
            return json({ error: "malformed" }, 400);
        }
        try {
            return await handleWithStore(request, this.#environment, store);
        } catch {
            return json({ error: "internal" }, 500);
        }
    }
}

/** Handle a private-group route, or return undefined for another Worker route. */
export async function handleCloudflarePrivateGroupRequest(
    request: Request,
    environment: MurmurCloudflareEnvironment,
): Promise<Response | undefined> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(PRIVATE_GROUP_PREFIX)) return undefined;
    if (request.method === "POST" && GROUP_PATHS.has(url.pathname)) {
        let opaqueGroupId: Uint8Array;
        try {
            opaqueGroupId = parseCanonicalBytes(request.headers.get("x-murmur-private-group"), 32);
        } catch {
            return json({ error: "malformed" }, 400);
        }
        const encodedGroupId = encodeBase64Url(opaqueGroupId);
        const id = environment.MURMUR_PRIVATE_GROUPS.idFromName(encodedGroupId);
        try {
            return await environment.MURMUR_PRIVATE_GROUPS.get(id).fetch(request);
        } catch {
            return json({ error: "internal" }, 500);
        }
    }
    try {
        return await handleWithStore(request, environment, ingressStore);
    } catch {
        return json({ error: "internal" }, 500);
    }
}
