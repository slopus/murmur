import {
    decodeBase64Url,
    decodeSignedRelayEventWire,
    encodeBase64Url,
    encodeSignedRelayEventWire,
    equalBytes,
    utf8Decode,
    utf8Encode,
    type SignedRelayEvent,
} from "@slopus/murmur";
import type { CliGroupMessage, CliStoredGroupMessage } from "../types.js";

const MAXIMUM_GROUP_NAME_BYTES = 128;
const MAXIMUM_EPOCH_STATE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_WELCOME_BYTES = 1024 * 1024;
const MAXIMUM_TREE_BYTES = 16 * 1024 * 1024;
const MAXIMUM_MARKERS = 100_000;
const MAXIMUM_GROUP_TEXT_BYTES = 512 * 1024;

/** Durable secret-bearing MLS group record. */
export interface CliGroupRecord {
    readonly name: string;
    readonly epochState: Uint8Array;
    readonly persistenceGeneration: bigint;
    readonly appliedCommitFingerprints: readonly Uint8Array[];
    readonly appliedApplicationFingerprints: readonly Uint8Array[];
}

/** Authenticated pairwise invitation carrying one Welcome and external tree. */
export interface CliGroupInvitation {
    readonly name: string;
    readonly groupId: Uint8Array;
    readonly welcome: Uint8Array;
    readonly tree: Uint8Array;
    readonly keyPackageReference: Uint8Array;
    readonly commitFingerprint: Uint8Array;
}

/** Exact application outbox entry for group publication ordering. */
export interface CliGroupOutbound {
    readonly kind: "invitation" | "commit" | "application" | "document";
    readonly groupId: string;
    readonly event: SignedRelayEvent;
    readonly messageKey?: string;
}

function record(value: unknown, fields: readonly string[], name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const keys = Object.keys(value);
    if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function canonicalIdentifier(value: unknown, bytes: number, name: string): Uint8Array {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (decoded.length !== bytes || encodeBase64Url(decoded) !== value) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function validGroupId(value: unknown): value is string {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
        return false;
    }
    const decoded = decodeBase64Url(value);
    return decoded.length === 32 && encodeBase64Url(decoded) === value;
}

function validateName(name: string): void {
    const bytes = utf8Encode(name);
    if (bytes.length === 0 || bytes.length > MAXIMUM_GROUP_NAME_BYTES) {
        throw new Error("Invalid CLI group name");
    }
}

function decodeMarkers(value: unknown, name: string): readonly Uint8Array[] {
    if (!Array.isArray(value) || value.length > MAXIMUM_MARKERS) {
        throw new Error(`Invalid ${name}`);
    }
    const markers = value.map((marker) => canonicalIdentifier(marker, 32, name));
    if (new Set(markers.map(encodeBase64Url)).size !== markers.length) {
        throw new Error(`Duplicate ${name}`);
    }
    return markers;
}

/** Encode one secret-bearing group checkpoint and replay-marker set. */
export function encodeCliGroupRecord(group: CliGroupRecord): Uint8Array {
    validateName(group.name);
    if (
        group.epochState.length === 0 ||
        group.epochState.length > MAXIMUM_EPOCH_STATE_BYTES ||
        group.persistenceGeneration < 0n ||
        group.persistenceGeneration > 0xffff_ffff_ffff_ffffn ||
        group.appliedCommitFingerprints.length > MAXIMUM_MARKERS ||
        group.appliedApplicationFingerprints.length > MAXIMUM_MARKERS
    ) {
        throw new Error("Invalid CLI group record");
    }
    for (const marker of [
        ...group.appliedCommitFingerprints,
        ...group.appliedApplicationFingerprints,
    ]) {
        if (marker.length !== 32) {
            throw new Error("Invalid CLI group replay marker");
        }
    }
    return utf8Encode(
        JSON.stringify({
            version: 1,
            name: group.name,
            epochState: encodeBase64Url(group.epochState),
            persistenceGeneration: group.persistenceGeneration.toString(),
            appliedCommitFingerprints: group.appliedCommitFingerprints.map(encodeBase64Url),
            appliedApplicationFingerprints:
                group.appliedApplicationFingerprints.map(encodeBase64Url),
        }),
    );
}

/** Decode one canonical secret-bearing group checkpoint. */
export function decodeCliGroupRecord(bytes: Uint8Array): CliGroupRecord {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        [
            "version",
            "name",
            "epochState",
            "persistenceGeneration",
            "appliedCommitFingerprints",
            "appliedApplicationFingerprints",
        ],
        "CLI group record",
    );
    if (
        value.version !== 1 ||
        typeof value.name !== "string" ||
        typeof value.epochState !== "string" ||
        typeof value.persistenceGeneration !== "string" ||
        !/^(?:0|[1-9]\d*)$/.test(value.persistenceGeneration)
    ) {
        throw new Error("Invalid CLI group record");
    }
    validateName(value.name);
    const group: CliGroupRecord = {
        name: value.name,
        epochState: decodeBase64Url(value.epochState),
        persistenceGeneration: BigInt(value.persistenceGeneration),
        appliedCommitFingerprints: decodeMarkers(
            value.appliedCommitFingerprints,
            "CLI applied Commit fingerprints",
        ),
        appliedApplicationFingerprints: decodeMarkers(
            value.appliedApplicationFingerprints,
            "CLI applied application fingerprints",
        ),
    };
    if (
        group.epochState.length === 0 ||
        group.epochState.length > MAXIMUM_EPOCH_STATE_BYTES ||
        group.persistenceGeneration > 0xffff_ffff_ffff_ffffn ||
        !equalBytes(encodeCliGroupRecord(group), bytes)
    ) {
        throw new Error("Non-canonical CLI group record");
    }
    return group;
}

/** Encode one pairwise group invitation as a direct-message text payload. */
export function encodeCliGroupInvitation(invitation: CliGroupInvitation): string {
    validateName(invitation.name);
    if (
        invitation.groupId.length === 0 ||
        invitation.groupId.length > 255 ||
        invitation.welcome.length === 0 ||
        invitation.welcome.length > MAXIMUM_WELCOME_BYTES ||
        invitation.tree.length === 0 ||
        invitation.tree.length > MAXIMUM_TREE_BYTES ||
        invitation.keyPackageReference.length !== 32 ||
        invitation.commitFingerprint.length !== 32
    ) {
        throw new Error("Invalid CLI group invitation");
    }
    return JSON.stringify({
        kind: "murmur.group-invitation.v1",
        name: invitation.name,
        groupId: encodeBase64Url(invitation.groupId),
        welcome: encodeBase64Url(invitation.welcome),
        tree: encodeBase64Url(invitation.tree),
        keyPackageReference: encodeBase64Url(invitation.keyPackageReference),
        commitFingerprint: encodeBase64Url(invitation.commitFingerprint),
    });
}

/** Decode one canonical pairwise group invitation, or return undefined for normal text. */
export function decodeCliGroupInvitation(text: string): CliGroupInvitation | undefined {
    let parsed: unknown;
    try {
        parsed = JSON.parse(text) as unknown;
    } catch {
        return undefined;
    }
    if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed) ||
        (parsed as Record<string, unknown>).kind !== "murmur.group-invitation.v1"
    ) {
        return undefined;
    }
    const value = record(
        parsed,
        ["kind", "name", "groupId", "welcome", "tree", "keyPackageReference", "commitFingerprint"],
        "CLI group invitation",
    );
    if (
        typeof value.name !== "string" ||
        typeof value.groupId !== "string" ||
        typeof value.welcome !== "string" ||
        typeof value.tree !== "string"
    ) {
        throw new Error("Invalid CLI group invitation");
    }
    const invitation: CliGroupInvitation = {
        name: value.name,
        groupId: decodeBase64Url(value.groupId),
        welcome: decodeBase64Url(value.welcome),
        tree: decodeBase64Url(value.tree),
        keyPackageReference: canonicalIdentifier(
            value.keyPackageReference,
            32,
            "CLI invitation KeyPackage reference",
        ),
        commitFingerprint: canonicalIdentifier(
            value.commitFingerprint,
            32,
            "CLI invitation Commit fingerprint",
        ),
    };
    if (encodeCliGroupInvitation(invitation) !== text) {
        throw new Error("Non-canonical CLI group invitation");
    }
    return invitation;
}

/** Encode authenticated user text for an MLS application message. */
export function encodeCliGroupMessage(message: CliGroupMessage): Uint8Array {
    const textBytes = utf8Encode(message.text);
    if (
        !/^[A-Za-z0-9_-]{22}$/.test(message.id) ||
        canonicalIdentifier(message.id, 16, "CLI group message ID").length !== 16 ||
        !Number.isSafeInteger(message.sentAt) ||
        message.sentAt < 0 ||
        textBytes.length > MAXIMUM_GROUP_TEXT_BYTES
    ) {
        throw new Error("Invalid CLI group message");
    }
    return utf8Encode(
        JSON.stringify({
            kind: "murmur.group-message.v1",
            id: message.id,
            sentAt: message.sentAt,
            text: message.text,
        }),
    );
}

/** Decode canonical authenticated MLS group application text. */
export function decodeCliGroupMessage(bytes: Uint8Array): CliGroupMessage {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["kind", "id", "sentAt", "text"],
        "CLI group message",
    );
    if (
        value.kind !== "murmur.group-message.v1" ||
        typeof value.id !== "string" ||
        typeof value.sentAt !== "number" ||
        typeof value.text !== "string"
    ) {
        throw new Error("Invalid CLI group message");
    }
    const message: CliGroupMessage = {
        id: value.id,
        sentAt: value.sentAt,
        text: value.text,
    };
    if (!equalBytes(encodeCliGroupMessage(message), bytes)) {
        throw new Error("Non-canonical CLI group message");
    }
    return message;
}

/** Encode one durable group history record. */
export function encodeCliStoredGroupMessage(stored: CliStoredGroupMessage): Uint8Array {
    if (
        !Number.isSafeInteger(stored.sequence) ||
        stored.sequence < 1 ||
        !validGroupId(stored.groupId) ||
        !Number.isSafeInteger(stored.sender) ||
        stored.sender < 0 ||
        !["incoming", "outgoing"].includes(stored.direction) ||
        !["received", "pending", "sent"].includes(stored.status)
    ) {
        throw new Error("Invalid stored CLI group message");
    }
    const message = encodeCliGroupMessage(stored.message);
    return utf8Encode(
        JSON.stringify({
            version: 1,
            sequence: stored.sequence,
            groupId: stored.groupId,
            direction: stored.direction,
            status: stored.status,
            sender: stored.sender,
            message: encodeBase64Url(message),
        }),
    );
}

/** Decode one canonical durable group history record. */
export function decodeCliStoredGroupMessage(bytes: Uint8Array): CliStoredGroupMessage {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "sequence", "groupId", "direction", "status", "sender", "message"],
        "stored CLI group message",
    );
    if (
        value.version !== 1 ||
        typeof value.sequence !== "number" ||
        typeof value.groupId !== "string" ||
        (value.direction !== "incoming" && value.direction !== "outgoing") ||
        !["received", "pending", "sent"].includes(value.status as string) ||
        typeof value.sender !== "number" ||
        typeof value.message !== "string"
    ) {
        throw new Error("Invalid stored CLI group message");
    }
    const stored: CliStoredGroupMessage = {
        sequence: value.sequence,
        groupId: value.groupId,
        direction: value.direction,
        status: value.status as CliStoredGroupMessage["status"],
        sender: value.sender,
        message: decodeCliGroupMessage(decodeBase64Url(value.message)),
    };
    if (!equalBytes(encodeCliStoredGroupMessage(stored), bytes)) {
        throw new Error("Non-canonical stored CLI group message");
    }
    return stored;
}

/** Encode one exact group application outbox entry. */
export function encodeCliGroupOutbound(outbound: CliGroupOutbound): Uint8Array {
    if (!validGroupId(outbound.groupId)) {
        throw new Error("Invalid CLI group outbox group");
    }
    return utf8Encode(
        JSON.stringify({
            version: 1,
            kind: outbound.kind,
            groupId: outbound.groupId,
            event: encodeBase64Url(encodeSignedRelayEventWire(outbound.event)),
            messageKey: outbound.messageKey ?? null,
        }),
    );
}

/** Decode one canonical exact group application outbox entry. */
export function decodeCliGroupOutbound(bytes: Uint8Array): CliGroupOutbound {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "kind", "groupId", "event", "messageKey"],
        "CLI group outbox",
    );
    if (
        value.version !== 1 ||
        !["invitation", "commit", "application", "document"].includes(value.kind as string) ||
        !validGroupId(value.groupId) ||
        typeof value.event !== "string" ||
        (value.messageKey !== null &&
            (typeof value.messageKey !== "string" ||
                value.messageKey.length === 0 ||
                value.messageKey.length > 4096)) ||
        (value.kind === "application") !== (typeof value.messageKey === "string")
    ) {
        throw new Error("Invalid CLI group outbox");
    }
    const outbound: CliGroupOutbound = {
        kind: value.kind as CliGroupOutbound["kind"],
        groupId: value.groupId,
        event: decodeSignedRelayEventWire(decodeBase64Url(value.event)),
        ...(typeof value.messageKey === "string" ? { messageKey: value.messageKey } : {}),
    };
    if (!equalBytes(encodeCliGroupOutbound(outbound), bytes)) {
        throw new Error("Non-canonical CLI group outbox");
    }
    return outbound;
}
