import type { MurmurStore } from "../../../storage/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    zeroBytes,
} from "../../../utils/index.js";

const INVITATION_PREFIX = "murmur/invitations/v1/";
const MAXIMUM_OUTSTANDING_INVITATIONS = 32;

interface InvitationStateRecord {
    readonly version: 1;
    readonly digest: Uint8Array;
    readonly expiresAt: number;
    readonly keyPackageReferences: readonly Uint8Array[];
    readonly revocationPending: boolean;
}

function key(digest: Uint8Array): string {
    if (!(digest instanceof Uint8Array) || digest.length !== 32) {
        throw new Error("Invalid invitation digest");
    }
    return `${INVITATION_PREFIX}${encodeBase64Url(digest)}`;
}

function encode(record: InvitationStateRecord): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        digest: encodeBase64Url(record.digest),
        expiresAt: record.expiresAt,
        keyPackageReferences: record.keyPackageReferences.map(encodeBase64Url),
        revocationPending: record.revocationPending,
    });
}

function decode(bytes: Uint8Array): InvitationStateRecord {
    let value: unknown;
    try {
        value = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        throw new Error("Invalid durable invitation state");
    }
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid durable invitation state");
    }
    const input = value as Record<string, unknown>;
    const referenceValues = input.keyPackageReferences;
    const fields = ["version", "digest", "expiresAt", "keyPackageReferences", "revocationPending"];
    if (
        fields.some((field) => !Object.hasOwn(input, field)) ||
        Object.keys(input).some((field) => !fields.includes(field)) ||
        input.version !== 1 ||
        typeof input.digest !== "string" ||
        typeof input.expiresAt !== "number" ||
        !Number.isSafeInteger(input.expiresAt) ||
        input.expiresAt < 0 ||
        !Array.isArray(referenceValues) ||
        referenceValues.length < 1 ||
        referenceValues.length > 32 ||
        referenceValues.some((entry) => typeof entry !== "string") ||
        typeof input.revocationPending !== "boolean"
    ) {
        throw new Error("Invalid durable invitation state");
    }
    const digest = decodeBase64Url(input.digest);
    const references = referenceValues.map((entry) => decodeBase64Url(entry as string));
    const record = recordValue(digest, input.expiresAt, references, input.revocationPending);
    const canonical = encode(record);
    if (
        digest.length !== 32 ||
        encodeBase64Url(digest) !== input.digest ||
        references.some(
            (reference, index) =>
                reference.length !== 32 || encodeBase64Url(reference) !== referenceValues[index],
        ) ||
        new Set(references.map(encodeBase64Url)).size !== references.length ||
        !equalBytes(canonical, bytes)
    ) {
        zeroBytes(canonical);
        throw new Error("Invalid durable invitation state");
    }
    zeroBytes(canonical);
    return record;
}

function recordValue(
    digest: Uint8Array,
    expiresAt: number,
    references: readonly Uint8Array[],
    revocationPending: boolean,
): InvitationStateRecord {
    return {
        version: 1,
        digest,
        expiresAt,
        keyPackageReferences: Object.freeze(references),
        revocationPending,
    };
}

/** Bounded durable mapping from invitation digests to their private one-use KeyPackages. */
export class InvitationState {
    readonly #store: MurmurStore;
    readonly #now: () => number;

    constructor(store: MurmurStore, now: () => number) {
        this.#store = store;
        this.#now = now;
    }

    async record(
        digest: Uint8Array,
        references: readonly Uint8Array[],
        expiresAt: number,
    ): Promise<void> {
        const entryKey = key(digest);
        const now = this.#now();
        if (
            !Array.isArray(references) ||
            references.length < 1 ||
            references.length > MAXIMUM_OUTSTANDING_INVITATIONS ||
            references.some(
                (reference) => !(reference instanceof Uint8Array) || reference.length !== 32,
            ) ||
            new Set(references.map(encodeBase64Url)).size !== references.length ||
            !Number.isSafeInteger(expiresAt) ||
            expiresAt <= now
        ) {
            throw new Error("Invalid invitation state");
        }
        await this.#store.transaction(async (transaction) => {
            const page = await transaction.scan(INVITATION_PREFIX, {
                limit: MAXIMUM_OUTSTANDING_INVITATIONS + 1,
            });
            let active = 0;
            try {
                for (const [existingKey, bytes] of page) {
                    const existing = decode(bytes);
                    if (existing.expiresAt <= now) {
                        await transaction.delete(existingKey);
                    } else {
                        active += 1;
                    }
                    for (const reference of existing.keyPackageReferences) zeroBytes(reference);
                    zeroBytes(existing.digest);
                }
            } finally {
                for (const bytes of page.values()) zeroBytes(bytes);
            }
            if (active >= MAXIMUM_OUTSTANDING_INVITATIONS) {
                throw new Error("Outstanding invitation capacity exceeded");
            }
            const record = recordValue(
                digest.slice(),
                expiresAt,
                references.map((reference) => reference.slice()),
                false,
            );
            const bytes = encode(record);
            try {
                await transaction.set(entryKey, bytes);
            } finally {
                zeroBytes(bytes);
                zeroBytes(record.digest);
                for (const reference of record.keyPackageReferences) zeroBytes(reference);
            }
        });
    }

    async begin(digest: Uint8Array | null): Promise<readonly Uint8Array[]> {
        return this.#store.transaction(async (transaction) => {
            const page = await transaction.scan(INVITATION_PREFIX, {
                limit: MAXIMUM_OUTSTANDING_INVITATIONS + 1,
            });
            if (page.size > MAXIMUM_OUTSTANDING_INVITATIONS) {
                for (const bytes of page.values()) zeroBytes(bytes);
                throw new Error("Outstanding invitation capacity exceeded");
            }
            const references: Uint8Array[] = [];
            try {
                for (const [entryKey, bytes] of page) {
                    const record = decode(bytes);
                    try {
                        if (record.expiresAt <= this.#now()) {
                            await transaction.delete(entryKey);
                            continue;
                        }
                        if (digest !== null && !equalBytes(record.digest, digest)) {
                            continue;
                        }
                        references.push(
                            ...record.keyPackageReferences.map((reference) => reference.slice()),
                        );
                        const encoded = encode({ ...record, revocationPending: true });
                        try {
                            await transaction.set(entryKey, encoded);
                        } finally {
                            zeroBytes(encoded);
                        }
                    } finally {
                        zeroBytes(record.digest);
                        for (const reference of record.keyPackageReferences) zeroBytes(reference);
                    }
                }
                return Object.freeze(references);
            } finally {
                for (const bytes of page.values()) zeroBytes(bytes);
            }
        });
    }

    async pendingReferences(): Promise<readonly Uint8Array[]> {
        const page = await this.#store.scan(INVITATION_PREFIX, {
            limit: MAXIMUM_OUTSTANDING_INVITATIONS + 1,
        });
        if (page.size > MAXIMUM_OUTSTANDING_INVITATIONS) {
            for (const bytes of page.values()) zeroBytes(bytes);
            throw new Error("Outstanding invitation capacity exceeded");
        }
        const references: Uint8Array[] = [];
        try {
            for (const bytes of page.values()) {
                const record = decode(bytes);
                if (record.revocationPending) {
                    references.push(
                        ...record.keyPackageReferences.map((reference) => reference.slice()),
                    );
                }
                zeroBytes(record.digest);
                for (const reference of record.keyPackageReferences) zeroBytes(reference);
            }
            return Object.freeze(references);
        } finally {
            for (const bytes of page.values()) zeroBytes(bytes);
        }
    }

    async complete(digest: Uint8Array | null): Promise<void> {
        await this.#store.transaction(async (transaction) => {
            if (digest !== null) {
                await transaction.delete(key(digest));
                return;
            }
            const page = await transaction.scan(INVITATION_PREFIX, {
                limit: MAXIMUM_OUTSTANDING_INVITATIONS + 1,
            });
            try {
                if (page.size > MAXIMUM_OUTSTANDING_INVITATIONS) {
                    throw new Error("Outstanding invitation capacity exceeded");
                }
                for (const entryKey of page.keys()) await transaction.delete(entryKey);
            } finally {
                for (const bytes of page.values()) zeroBytes(bytes);
            }
        });
    }
}
