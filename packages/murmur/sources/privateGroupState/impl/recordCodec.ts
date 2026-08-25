import { gcm } from "@noble/ciphers/aes";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";
import type { PrivateGroupParameters } from "../../privateGroups/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    zeroBytes,
} from "../../utils/index.js";
import type {
    PrivateGroupMemberEntry,
    PrivateGroupRecordContent,
    PrivateGroupStateRecord,
    StoredPrivateGroupStateRecord,
} from "../types.js";

interface RecordMetadata {
    readonly attributes: Uint8Array;
    readonly mlsStateDigest: Uint8Array;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    const length = Math.min(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return left.length - right.length;
}

/** Return a canonical defensive copy of member entries. */
export function canonicalMemberEntries(
    members: readonly PrivateGroupMemberEntry[],
): readonly PrivateGroupMemberEntry[] {
    const result = members
        .map((member) => ({ entry: member.entry.slice(), role: member.role }))
        .sort((left, right) => compareBytes(left.entry, right.entry));
    for (let index = 0; index < result.length; index += 1) {
        const member = result[index];
        if (member === undefined || member.entry.length < 1) {
            throw new Error("Invalid private-group member entry");
        }
        if (index > 0 && equalBytes(result[index - 1]!.entry, member.entry)) {
            throw new Error("Duplicate private-group member entry");
        }
    }
    if (!result.some((member) => member.role === "owner")) {
        throw new Error("Private group must retain at least one owner");
    }
    return result;
}

function recordValue(record: PrivateGroupStateRecord, includeAuthenticator: boolean) {
    return {
        version: record.version,
        opaqueGroupId: encodeBase64Url(record.opaqueGroupId),
        publicParameters: encodeBase64Url(record.publicParameters),
        revision: record.revision,
        previousRevisionHash:
            record.previousRevisionHash === null
                ? null
                : encodeBase64Url(record.previousRevisionHash),
        members: record.members.map((member) => ({
            entry: encodeBase64Url(member.entry),
            role: member.role,
        })),
        sealedState: encodeBase64Url(record.sealedState),
        ...(includeAuthenticator
            ? { revisionAuthenticator: encodeBase64Url(record.revisionAuthenticator) }
            : {}),
    };
}

/** Canonically encode a complete private-group record. */
export function encodePrivateGroupStateRecord(record: PrivateGroupStateRecord): Uint8Array {
    return canonicalJsonBytes(recordValue(record, true));
}

/** Canonically encode a record without its member-only HMAC. */
export function encodeUnsignedPrivateGroupStateRecord(record: PrivateGroupStateRecord): Uint8Array {
    return canonicalJsonBytes(recordValue(record, false));
}

/** Hash a complete canonical record for parent ordering and rollback detection. */
export function privateGroupStateRecordHash(record: PrivateGroupStateRecord): Uint8Array {
    return sha256(encodePrivateGroupStateRecord(record));
}

function manifestBytes(
    record: Omit<PrivateGroupStateRecord, "sealedState" | "revisionAuthenticator">,
): Uint8Array {
    return canonicalJsonBytes({
        domain: "murmur.private-group-state.record-manifest.v1",
        version: record.version,
        opaqueGroupId: encodeBase64Url(record.opaqueGroupId),
        publicParameters: encodeBase64Url(record.publicParameters),
        revision: record.revision,
        previousRevisionHash:
            record.previousRevisionHash === null
                ? null
                : encodeBase64Url(record.previousRevisionHash),
        members: record.members.map((member) => ({
            entry: encodeBase64Url(member.entry),
            role: member.role,
        })),
    });
}

/** Digest the authenticated MLS logical-account snapshot bound to one revision. */
export function privateGroupMlsStateDigest(content: PrivateGroupRecordContent): Uint8Array {
    if (content.session.status !== "active") {
        throw new Error("Private-group state requires an active MLS session snapshot");
    }
    const members = content.session.members
        .map((member) => {
            if (member.length !== 32) throw new Error("Invalid MLS logical account identifier");
            return encodeBase64Url(member);
        })
        .sort();
    if (new Set(members).size !== members.length) {
        throw new Error("MLS logical account roster contains a duplicate");
    }
    return sha256(
        canonicalJsonBytes({
            domain: "murmur.private-group-state.mls-binding.v1",
            id: encodeBase64Url(content.session.id),
            status: content.session.status,
            descriptor: encodeBase64Url(content.session.descriptor),
            members,
            committer: encodeBase64Url(content.session.committer),
        }),
    );
}

function encodeMetadata(metadata: RecordMetadata): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        attributes: encodeBase64Url(metadata.attributes),
        mlsStateDigest: encodeBase64Url(metadata.mlsStateDigest),
    });
}

function decodeMetadata(value: Uint8Array): RecordMetadata {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(value));
    } catch {
        throw new Error("Invalid encrypted private-group metadata");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid encrypted private-group metadata");
    }
    const input = parsed as Record<string, unknown>;
    if (
        Object.keys(input).sort().join(",") !== "attributes,mlsStateDigest,version" ||
        input.version !== 1 ||
        typeof input.attributes !== "string" ||
        typeof input.mlsStateDigest !== "string"
    ) {
        throw new Error("Invalid encrypted private-group metadata");
    }
    return {
        attributes: decodeBase64Url(input.attributes),
        mlsStateDigest: decodeBase64Url(input.mlsStateDigest),
    };
}

/** Construct and authenticate one encrypted canonical record revision. */
export function createPrivateGroupStateRecord(options: {
    readonly parameters: PrivateGroupParameters;
    readonly publicParameters: Uint8Array;
    readonly revision: number;
    readonly previousRevisionHash: Uint8Array | null;
    readonly members: readonly PrivateGroupMemberEntry[];
    readonly content: PrivateGroupRecordContent;
}): PrivateGroupStateRecord {
    if (!Number.isSafeInteger(options.revision) || options.revision < 1) {
        throw new Error("Invalid private-group record revision");
    }
    if (
        (options.revision === 1) !== (options.previousRevisionHash === null) ||
        (options.previousRevisionHash !== null && options.previousRevisionHash.length !== 32)
    ) {
        throw new Error("Invalid private-group revision parent");
    }
    const members = canonicalMemberEntries(options.members);
    const manifest = {
        version: 1 as const,
        opaqueGroupId: options.parameters.opaqueGroupId.slice(),
        publicParameters: options.publicParameters.slice(),
        revision: options.revision,
        previousRevisionHash: options.previousRevisionHash?.slice() ?? null,
        members,
    };
    const nonce = randomBytes(12);
    const metadata = encodeMetadata({
        attributes: options.content.attributes,
        mlsStateDigest: privateGroupMlsStateDigest(options.content),
    });
    let ciphertext: Uint8Array;
    try {
        ciphertext = gcm(
            options.parameters.metadataKeys.encryptionKey,
            nonce,
            manifestBytes(manifest),
        ).encrypt(metadata);
    } finally {
        zeroBytes(metadata);
    }
    const sealedState = new Uint8Array(nonce.length + ciphertext.length);
    sealedState.set(nonce);
    sealedState.set(ciphertext, nonce.length);
    const unsigned: PrivateGroupStateRecord = {
        ...manifest,
        sealedState,
        revisionAuthenticator: new Uint8Array(32),
    };
    return {
        ...unsigned,
        revisionAuthenticator: hmac(
            sha256,
            options.parameters.metadataKeys.authenticationKey,
            encodeUnsignedPrivateGroupStateRecord(unsigned),
        ),
    };
}

function equalMemberEntries(
    left: readonly PrivateGroupMemberEntry[],
    right: readonly PrivateGroupMemberEntry[],
): boolean {
    if (left.length !== right.length) return false;
    return left.every(
        (member, index) =>
            member.role === right[index]?.role && equalBytes(member.entry, right[index]!.entry),
    );
}

/** Verify, decrypt, and bind one service response to the current MLS snapshot. */
export function openPrivateGroupStateRecord(options: {
    readonly stored: StoredPrivateGroupStateRecord;
    readonly parameters: PrivateGroupParameters;
    readonly publicParameters: Uint8Array;
    readonly expectedMembers: readonly PrivateGroupMemberEntry[];
    readonly content: Pick<PrivateGroupRecordContent, "session">;
}): Uint8Array {
    const record = options.stored.record;
    if (
        record.version !== 1 ||
        !equalBytes(record.opaqueGroupId, options.parameters.opaqueGroupId) ||
        !equalBytes(record.publicParameters, options.publicParameters) ||
        !equalBytes(privateGroupStateRecordHash(record), options.stored.revisionHash)
    ) {
        throw new Error("Private-group canonical record encoding or scope is invalid");
    }
    const canonicalMembers = canonicalMemberEntries(record.members);
    const expectedMembers = canonicalMemberEntries(options.expectedMembers);
    if (!equalMemberEntries(canonicalMembers, record.members)) {
        throw new Error("Private-group member entries are not canonically ordered");
    }
    if (!equalMemberEntries(canonicalMembers, expectedMembers)) {
        throw new Error("Private-group roster is not reflected in authenticated MLS state");
    }
    const expectedAuthenticator = hmac(
        sha256,
        options.parameters.metadataKeys.authenticationKey,
        encodeUnsignedPrivateGroupStateRecord(record),
    );
    if (!equalBytes(expectedAuthenticator, record.revisionAuthenticator)) {
        throw new Error("Private-group revision authenticator is invalid");
    }
    if (record.sealedState.length < 28) throw new Error("Private-group sealed state is invalid");
    const nonce = record.sealedState.subarray(0, 12);
    const ciphertext = record.sealedState.subarray(12);
    const manifest = {
        version: record.version,
        opaqueGroupId: record.opaqueGroupId,
        publicParameters: record.publicParameters,
        revision: record.revision,
        previousRevisionHash: record.previousRevisionHash,
        members: record.members,
    };
    let plaintext: Uint8Array | undefined;
    try {
        plaintext = gcm(
            options.parameters.metadataKeys.encryptionKey,
            nonce,
            manifestBytes(manifest),
        ).decrypt(ciphertext);
        const metadata = decodeMetadata(plaintext);
        const expectedMlsDigest = privateGroupMlsStateDigest({
            attributes: new Uint8Array(),
            session: options.content.session,
            roles: [],
        });
        if (!equalBytes(metadata.mlsStateDigest, expectedMlsDigest)) {
            throw new Error("Private-group revision is not bound to the current MLS state");
        }
        return metadata.attributes;
    } catch (error: unknown) {
        if (error instanceof Error && error.message.startsWith("Private-group")) throw error;
        throw new Error("Private-group encrypted metadata is invalid");
    } finally {
        if (plaintext !== undefined) zeroBytes(plaintext);
    }
}
