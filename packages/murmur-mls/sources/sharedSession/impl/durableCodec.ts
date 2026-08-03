import {
    canonicalJsonBytes,
    decodeBase64Url,
    decodeSignedRelayEventWire,
    encodeBase64Url,
    encodeSignedRelayEventWire,
    equalBytes,
    utf8Decode,
    type EncryptedFileDescriptor,
    type IdentityPublicKeys,
    type JsonValue,
    type SignedRelayEvent,
} from "@slopus/murmur";
import type { SharedSessionEntry, SharedSessionInvitation, SharedSessionState } from "../types.js";
import {
    MAX_SHARED_SESSION_HISTORY_OFFERS,
    MAX_SHARED_SESSION_OFFER_PAGES,
    MAX_SHARED_SESSION_PENDING_ENTRIES,
    SharedSessionProtocolError,
} from "../types.js";
import {
    sharedSessionEntryFromJson,
    sharedSessionEntryToJson,
    sharedSessionFileFromJson,
    sharedSessionFileToJson,
    sharedSessionStateFromJson,
    sharedSessionStateToJson,
} from "./frameCodec.js";

const MAXIMUM_EPOCH_STATE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_MARKERS = 100_000;

export interface DurableSharedSessionHistory {
    readonly discovery?: EncryptedFileDescriptor;
    readonly offerCount: number;
    readonly processOffer?: number;
    readonly pageIndex: number;
    readonly highestSequence: number;
    readonly pendingEntries: readonly SharedSessionEntry[];
}

export interface DurableSharedSessionRecord {
    readonly role: "owner" | "member";
    readonly state: SharedSessionState;
    readonly owner: IdentityPublicKeys;
    readonly epochState: Uint8Array;
    readonly persistenceGeneration: bigint;
    readonly appliedCommitFingerprints: readonly Uint8Array[];
    readonly appliedApplicationFingerprints: readonly Uint8Array[];
    readonly maximumSequence: number;
    readonly internalStatus: "active" | "stopping" | "stopped" | "terminated";
    readonly stateDirty: boolean;
    readonly pendingRemovePeerIds: readonly string[];
    readonly history?: DurableSharedSessionHistory;
}

export type DurableSharedSessionOutbox =
    | {
          readonly kind: "invitation";
          readonly shareId: string;
          readonly invitation: SharedSessionInvitation;
      }
    | {
          readonly kind: "application" | "commit";
          readonly shareId: string;
          readonly event: SignedRelayEvent;
      };

function record(value: unknown, fields: readonly string[], name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new SharedSessionProtocolError("invalid-frame", `Invalid ${name}`);
    }
    const keys = Object.keys(value);
    if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
        throw new SharedSessionProtocolError("invalid-frame", `Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function encodeIdentity(identity: IdentityPublicKeys): {
    readonly signingKey: string;
    readonly encryptionKey: string;
} {
    if (identity.signingKey.length !== 32 || identity.encryptionKey.length !== 32) {
        throw new Error("Invalid shared-session durable identity");
    }
    return {
        signingKey: encodeBase64Url(identity.signingKey),
        encryptionKey: encodeBase64Url(identity.encryptionKey),
    };
}

function decodeIdentity(value: unknown): IdentityPublicKeys {
    const identity = record(
        value,
        ["encryptionKey", "signingKey"],
        "shared-session durable identity",
    );
    if (typeof identity.signingKey !== "string" || typeof identity.encryptionKey !== "string") {
        throw new SharedSessionProtocolError(
            "invalid-frame",
            "Invalid shared-session durable identity",
        );
    }
    const result = {
        signingKey: decodeBase64Url(identity.signingKey),
        encryptionKey: decodeBase64Url(identity.encryptionKey),
    };
    encodeIdentity(result);
    return result;
}

function encodeMarkers(markers: readonly Uint8Array[]): readonly string[] {
    if (markers.length > MAXIMUM_MARKERS || markers.some((marker) => marker.length !== 32)) {
        throw new Error("Invalid shared-session replay markers");
    }
    const values = markers.map(encodeBase64Url);
    if (new Set(values).size !== values.length) {
        throw new Error("Duplicate shared-session replay marker");
    }
    return values;
}

function decodeMarkers(value: unknown): readonly Uint8Array[] {
    if (!Array.isArray(value) || value.some((marker) => typeof marker !== "string")) {
        throw new SharedSessionProtocolError("invalid-frame", "Invalid shared-session markers");
    }
    const markers = (value as string[]).map(decodeBase64Url);
    encodeMarkers(markers);
    return markers;
}

function encodeHistory(history: DurableSharedSessionHistory): JsonValue {
    if (
        !Number.isSafeInteger(history.offerCount) ||
        history.offerCount < 0 ||
        history.offerCount > MAX_SHARED_SESSION_HISTORY_OFFERS ||
        (history.processOffer !== undefined &&
            (!Number.isSafeInteger(history.processOffer) ||
                history.processOffer < 0 ||
                history.processOffer >= history.offerCount)) ||
        !Number.isSafeInteger(history.pageIndex) ||
        history.pageIndex < 0 ||
        history.pageIndex > MAX_SHARED_SESSION_OFFER_PAGES ||
        !Number.isSafeInteger(history.highestSequence) ||
        history.highestSequence < 0 ||
        history.pendingEntries.length > MAX_SHARED_SESSION_PENDING_ENTRIES
    ) {
        throw new Error("Invalid shared-session durable history");
    }
    return {
        discovery:
            history.discovery === undefined ? null : sharedSessionFileToJson(history.discovery),
        highestSequence: history.highestSequence,
        offerCount: history.offerCount,
        pageIndex: history.pageIndex,
        pendingEntries: history.pendingEntries.map(sharedSessionEntryToJson),
        processOffer: history.processOffer ?? null,
    };
}

function decodeHistory(value: unknown): DurableSharedSessionHistory {
    const history = record(
        value,
        [
            "discovery",
            "highestSequence",
            "offerCount",
            "pageIndex",
            "pendingEntries",
            "processOffer",
        ],
        "shared-session durable history",
    );
    if (
        (history.discovery !== null &&
            (typeof history.discovery !== "object" || history.discovery === null)) ||
        typeof history.highestSequence !== "number" ||
        typeof history.offerCount !== "number" ||
        typeof history.pageIndex !== "number" ||
        !Array.isArray(history.pendingEntries) ||
        (history.processOffer !== null && typeof history.processOffer !== "number")
    ) {
        throw new SharedSessionProtocolError(
            "invalid-frame",
            "Invalid shared-session durable history",
        );
    }
    const result: DurableSharedSessionHistory = {
        ...(history.discovery === null
            ? {}
            : { discovery: sharedSessionFileFromJson(history.discovery) }),
        highestSequence: history.highestSequence,
        offerCount: history.offerCount,
        pageIndex: history.pageIndex,
        pendingEntries: history.pendingEntries.map(sharedSessionEntryFromJson),
        ...(history.processOffer === null ? {} : { processOffer: history.processOffer }),
    };
    encodeHistory(result);
    return result;
}

/** Encode one secret-bearing shared-session checkpoint. */
export function encodeDurableSharedSessionRecord(
    recordValue: DurableSharedSessionRecord,
): Uint8Array {
    if (
        recordValue.epochState.length === 0 ||
        recordValue.epochState.length > MAXIMUM_EPOCH_STATE_BYTES ||
        recordValue.persistenceGeneration < 0n ||
        !Number.isSafeInteger(recordValue.maximumSequence) ||
        recordValue.maximumSequence < 0 ||
        recordValue.pendingRemovePeerIds.length > 256 ||
        new Set(recordValue.pendingRemovePeerIds).size !==
            recordValue.pendingRemovePeerIds.length ||
        (recordValue.history !== undefined &&
            (recordValue.history.highestSequence > recordValue.maximumSequence ||
                recordValue.history.pendingEntries.some(
                    (entry) =>
                        entry.shareId !== recordValue.state.shareId ||
                        entry.shareSequence <= recordValue.history!.highestSequence ||
                        entry.shareSequence > recordValue.maximumSequence,
                )))
    ) {
        throw new Error("Invalid shared-session durable record");
    }
    return canonicalJsonBytes({
        appliedApplicationFingerprints: encodeMarkers(recordValue.appliedApplicationFingerprints),
        appliedCommitFingerprints: encodeMarkers(recordValue.appliedCommitFingerprints),
        epochState: encodeBase64Url(recordValue.epochState),
        history: recordValue.history === undefined ? null : encodeHistory(recordValue.history),
        internalStatus: recordValue.internalStatus,
        maximumSequence: recordValue.maximumSequence,
        owner: encodeIdentity(recordValue.owner),
        pendingRemovePeerIds: recordValue.pendingRemovePeerIds,
        persistenceGeneration: recordValue.persistenceGeneration.toString(),
        role: recordValue.role,
        state: sharedSessionStateToJson(recordValue.state),
        stateDirty: recordValue.stateDirty,
        version: 1,
    });
}

/** Decode and canonicalize one secret-bearing shared-session checkpoint. */
export function decodeDurableSharedSessionRecord(bytes: Uint8Array): DurableSharedSessionRecord {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        [
            "appliedApplicationFingerprints",
            "appliedCommitFingerprints",
            "epochState",
            "history",
            "internalStatus",
            "maximumSequence",
            "owner",
            "pendingRemovePeerIds",
            "persistenceGeneration",
            "role",
            "state",
            "stateDirty",
            "version",
        ],
        "shared-session durable record",
    );
    if (
        value.version !== 1 ||
        (value.role !== "owner" && value.role !== "member") ||
        typeof value.epochState !== "string" ||
        typeof value.persistenceGeneration !== "string" ||
        !/^(0|[1-9]\d*)$/.test(value.persistenceGeneration) ||
        typeof value.maximumSequence !== "number" ||
        !["active", "stopping", "stopped", "terminated"].includes(value.internalStatus as string) ||
        typeof value.stateDirty !== "boolean" ||
        !Array.isArray(value.pendingRemovePeerIds) ||
        value.pendingRemovePeerIds.some((peer) => typeof peer !== "string") ||
        (value.history !== null && (typeof value.history !== "object" || value.history === null))
    ) {
        throw new SharedSessionProtocolError(
            "invalid-frame",
            "Invalid shared-session durable record",
        );
    }
    const result: DurableSharedSessionRecord = {
        role: value.role,
        state: sharedSessionStateFromJson(value.state),
        owner: decodeIdentity(value.owner),
        epochState: decodeBase64Url(value.epochState),
        persistenceGeneration: BigInt(value.persistenceGeneration),
        appliedCommitFingerprints: decodeMarkers(value.appliedCommitFingerprints),
        appliedApplicationFingerprints: decodeMarkers(value.appliedApplicationFingerprints),
        maximumSequence: value.maximumSequence,
        internalStatus: value.internalStatus as DurableSharedSessionRecord["internalStatus"],
        stateDirty: value.stateDirty,
        pendingRemovePeerIds: value.pendingRemovePeerIds as string[],
        ...(value.history === null ? {} : { history: decodeHistory(value.history) }),
    };
    if (!equalBytes(encodeDurableSharedSessionRecord(result), bytes)) {
        throw new SharedSessionProtocolError(
            "invalid-frame",
            "Non-canonical shared-session durable record",
        );
    }
    return result;
}

/** Encode one ordered exact-event or direct invitation outbox record. */
export function encodeDurableSharedSessionOutbox(outbox: DurableSharedSessionOutbox): Uint8Array {
    return canonicalJsonBytes(
        outbox.kind === "invitation"
            ? {
                  invitation: {
                      deliveryId: outbox.invitation.deliveryId,
                      recipient: encodeIdentity(outbox.invitation.recipient),
                      sentAt: outbox.invitation.sentAt,
                      text: outbox.invitation.text,
                  },
                  kind: outbox.kind,
                  shareId: outbox.shareId,
                  version: 1,
              }
            : {
                  event: encodeBase64Url(encodeSignedRelayEventWire(outbox.event)),
                  kind: outbox.kind,
                  shareId: outbox.shareId,
                  version: 1,
              },
    );
}

/** Decode one canonical ordered shared-session outbox record. */
export function decodeDurableSharedSessionOutbox(bytes: Uint8Array): DurableSharedSessionOutbox {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new SharedSessionProtocolError("invalid-frame", "Invalid shared-session outbox");
    }
    const kind = (parsed as Record<string, unknown>).kind;
    if (kind === "invitation") {
        const value = record(
            parsed,
            ["invitation", "kind", "shareId", "version"],
            "shared-session invitation outbox",
        );
        const invitation = record(
            value.invitation,
            ["deliveryId", "recipient", "sentAt", "text"],
            "shared-session durable invitation",
        );
        if (
            value.version !== 1 ||
            typeof value.shareId !== "string" ||
            typeof invitation.deliveryId !== "string" ||
            typeof invitation.sentAt !== "number" ||
            typeof invitation.text !== "string"
        ) {
            throw new SharedSessionProtocolError(
                "invalid-frame",
                "Invalid shared-session invitation outbox",
            );
        }
        const result: DurableSharedSessionOutbox = {
            kind,
            shareId: value.shareId,
            invitation: {
                deliveryId: invitation.deliveryId,
                recipient: decodeIdentity(invitation.recipient),
                sentAt: invitation.sentAt,
                text: invitation.text,
            },
        };
        if (!equalBytes(encodeDurableSharedSessionOutbox(result), bytes)) {
            throw new SharedSessionProtocolError(
                "invalid-frame",
                "Non-canonical shared-session invitation outbox",
            );
        }
        return result;
    }
    const value = record(
        parsed,
        ["event", "kind", "shareId", "version"],
        "shared-session MLS outbox",
    );
    if (
        value.version !== 1 ||
        (kind !== "application" && kind !== "commit") ||
        typeof value.shareId !== "string" ||
        typeof value.event !== "string"
    ) {
        throw new SharedSessionProtocolError("invalid-frame", "Invalid shared-session MLS outbox");
    }
    const result: DurableSharedSessionOutbox = {
        kind,
        shareId: value.shareId,
        event: decodeSignedRelayEventWire(decodeBase64Url(value.event)),
    };
    if (!equalBytes(encodeDurableSharedSessionOutbox(result), bytes)) {
        throw new SharedSessionProtocolError(
            "invalid-frame",
            "Non-canonical shared-session MLS outbox",
        );
    }
    return result;
}
