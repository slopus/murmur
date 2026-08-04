import type { SignedRelayEvent } from "../../transport/index.js";
import { decodeSignedRelayEventWire, encodeSignedRelayEventWire } from "../../transport/index.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

const MAXIMUM_RECORD_BYTES = 64 * 1024 * 1024;
const MAXIMUM_OPAQUE_BYTES = 1024 * 1024;

export type OutboxPurpose =
    | { readonly type: "friend-exchange"; readonly sourceId: string }
    | { readonly type: "friend-control" }
    | {
          readonly type: "group-invitation";
          readonly groupId: string;
          readonly operationId: string;
          readonly peerId: string;
      }
    | {
          readonly type: "group-application";
          readonly groupId: string;
          readonly operationId: string;
      }
    | {
          readonly type: "group-commit";
          readonly groupId: string;
          readonly operationId: string;
      };

export interface RelayOutboxRecord {
    readonly event: SignedRelayEvent;
    readonly purpose: OutboxPurpose;
    readonly attempted: boolean;
}

export interface ControlSelfMarker {
    readonly topicId: string;
    readonly sequence: bigint;
    readonly fingerprint: Uint8Array;
}

export interface DeferredInvitationRecord {
    readonly peer: Uint8Array;
    readonly messageId: string;
    readonly fingerprint: Uint8Array;
    readonly frame: Uint8Array;
}

export interface StoredGroup {
    readonly id: string;
    readonly descriptor: Uint8Array;
    readonly descriptorNonce: Uint8Array;
    readonly descriptorBinding: Uint8Array;
    readonly topicSecret: Uint8Array;
    readonly members: readonly Uint8Array[];
    readonly createdAt: number;
    readonly epoch: bigint;
    readonly persistenceGeneration: bigint;
    readonly status: "active" | "removed";
}

export interface GroupOperationAttempt {
    readonly eventId: string;
    readonly fingerprint: Uint8Array;
    readonly epoch: bigint;
}

export type GroupOperation =
    | {
          readonly id: string;
          readonly type: "send";
          readonly payload: Uint8Array;
          readonly createdAt: number;
          readonly attempt?: GroupOperationAttempt;
      }
    | {
          readonly id: string;
          readonly type: "add" | "remove";
          readonly peer: Uint8Array;
          readonly createdAt: number;
      };

export interface StagedGroupCommit {
    readonly operationId: string;
    readonly eventId: string;
    readonly fingerprint: Uint8Array;
    readonly currentEpoch: bigint;
    readonly currentGeneration: bigint;
    readonly nextEpoch: Uint8Array;
    readonly type: "add" | "remove";
    readonly peer: Uint8Array;
    readonly keyPackageReference?: Uint8Array;
    readonly welcome?: Uint8Array;
    readonly tree?: Uint8Array;
}

export interface StoredGroupEvent {
    readonly sequence: bigint;
    readonly sender: Uint8Array;
    readonly bytes: Uint8Array;
}

function object(value: unknown, fields: readonly string[], name: string): Record<string, unknown> {
    if (
        typeof value !== "object" ||
        value === null ||
        Array.isArray(value) ||
        Object.keys(value).length !== fields.length ||
        Object.keys(value).some((key) => !fields.includes(key))
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exactParsed(
    bytes: Uint8Array,
    fields: readonly string[],
    name: string,
): Record<string, unknown> {
    if (bytes.length > MAXIMUM_RECORD_BYTES) {
        throw new Error(`Invalid ${name}`);
    }
    return object(JSON.parse(utf8Decode(bytes)) as unknown, fields, name);
}

function bytes(
    value: unknown,
    name: string,
    maximum: number = MAXIMUM_OPAQUE_BYTES,
    exact?: number,
): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((maximum * 4) / 3)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (
        decoded.length > maximum ||
        (exact !== undefined && decoded.length !== exact) ||
        encodeBase64Url(decoded) !== value
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function id(value: unknown, name: string, decodedBytes: number): string {
    if (typeof value !== "string") {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = bytes(value, name, decodedBytes, decodedBytes);
    if (decoded.length !== decodedBytes) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function integer(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function uint64(value: unknown, name: string): bigint {
    if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > 0xffff_ffff_ffff_ffffn) {
        throw new Error(`Invalid ${name}`);
    }
    return parsed;
}

function nullableBytes(
    value: unknown,
    name: string,
    maximum?: number,
    exact?: number,
): Uint8Array | undefined {
    return value === null ? undefined : bytes(value, name, maximum, exact);
}

/** Encode one exact signed relay publication and its internal consequence. */
export function encodeRelayOutbox(record: RelayOutboxRecord): Uint8Array {
    const purpose =
        record.purpose.type === "friend-exchange"
            ? {
                  type: record.purpose.type,
                  sourceId: record.purpose.sourceId,
                  groupId: null,
                  operationId: null,
              }
            : record.purpose.type === "friend-control"
              ? {
                    type: record.purpose.type,
                    sourceId: null,
                    groupId: null,
                    operationId: null,
                }
              : record.purpose.type === "group-invitation"
                ? {
                      type: record.purpose.type,
                      sourceId: record.purpose.peerId,
                      groupId: record.purpose.groupId,
                      operationId: record.purpose.operationId,
                  }
                : {
                      type: record.purpose.type,
                      sourceId: null,
                      groupId: record.purpose.groupId,
                      operationId: record.purpose.operationId,
                  };
    return utf8Encode(
        JSON.stringify({
            version: 1,
            event: encodeBase64Url(encodeSignedRelayEventWire(record.event)),
            purpose,
            attempted: record.attempted,
        }),
    );
}

/** Decode one exact signed relay publication. */
export function decodeRelayOutbox(encoded: Uint8Array): RelayOutboxRecord {
    const value = exactParsed(
        encoded,
        ["version", "event", "purpose", "attempted"],
        "relay outbox",
    );
    if (
        value.version !== 1 ||
        typeof value.attempted !== "boolean" ||
        typeof value.purpose !== "object" ||
        value.purpose === null ||
        Array.isArray(value.purpose)
    ) {
        throw new Error("Invalid relay outbox");
    }
    const purpose = object(
        value.purpose,
        ["type", "sourceId", "groupId", "operationId"],
        "relay outbox purpose",
    );
    let decodedPurpose: OutboxPurpose;
    if (
        purpose.type === "friend-exchange" &&
        typeof purpose.sourceId === "string" &&
        purpose.groupId === null &&
        purpose.operationId === null
    ) {
        decodedPurpose = {
            type: "friend-exchange",
            sourceId: id(purpose.sourceId, "friend outbox source", 24),
        };
    } else if (
        purpose.type === "friend-control" &&
        purpose.sourceId === null &&
        purpose.groupId === null &&
        purpose.operationId === null
    ) {
        decodedPurpose = { type: "friend-control" };
    } else if (
        purpose.type === "group-invitation" &&
        typeof purpose.sourceId === "string" &&
        typeof purpose.groupId === "string" &&
        typeof purpose.operationId === "string"
    ) {
        decodedPurpose = {
            type: "group-invitation",
            peerId: id(purpose.sourceId, "group invitation peer", 32),
            groupId: id(purpose.groupId, "group ID", 32),
            operationId: id(purpose.operationId, "group operation ID", 24),
        };
    } else if (
        (purpose.type === "group-application" || purpose.type === "group-commit") &&
        purpose.sourceId === null &&
        typeof purpose.groupId === "string" &&
        typeof purpose.operationId === "string"
    ) {
        decodedPurpose = {
            type: purpose.type,
            groupId: id(purpose.groupId, "group ID", 32),
            operationId: id(purpose.operationId, "group operation ID", 24),
        };
    } else {
        throw new Error("Invalid relay outbox purpose");
    }
    const eventBytes = bytes(value.event, "relay outbox event", 4 * 1024 * 1024);
    try {
        return {
            event: decodeSignedRelayEventWire(eventBytes),
            purpose: decodedPurpose,
            attempted: value.attempted,
        };
    } finally {
        eventBytes.fill(0);
    }
}

/** Encode the bounded cursor consequence for one published control echo. */
export function encodeControlSelfMarker(marker: ControlSelfMarker): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 1,
            topicId: marker.topicId,
            sequence: marker.sequence.toString(),
            fingerprint: encodeBase64Url(marker.fingerprint),
        }),
    );
}

/** Decode one pending control-echo cursor consequence. */
export function decodeControlSelfMarker(encoded: Uint8Array): ControlSelfMarker {
    const value = exactParsed(
        encoded,
        ["version", "topicId", "sequence", "fingerprint"],
        "control self marker",
    );
    if (value.version !== 1) {
        throw new Error("Invalid control self marker");
    }
    return {
        topicId: id(value.topicId, "control topic ID", 32),
        sequence: uint64(value.sequence, "control sequence"),
        fingerprint: bytes(value.fingerprint, "control fingerprint", 32, 32),
    };
}

/** Encode one bounded deferred group invitation. */
export function encodeDeferredInvitation(record: DeferredInvitationRecord): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 1,
            peer: encodeBase64Url(record.peer),
            messageId: record.messageId,
            fingerprint: encodeBase64Url(record.fingerprint),
            frame: encodeBase64Url(record.frame),
        }),
    );
}

/** Decode one deferred group invitation. */
export function decodeDeferredInvitation(encoded: Uint8Array): DeferredInvitationRecord {
    const value = exactParsed(
        encoded,
        ["version", "peer", "messageId", "fingerprint", "frame"],
        "deferred invitation",
    );
    if (value.version !== 1) {
        throw new Error("Invalid deferred invitation");
    }
    let peer: Uint8Array | undefined;
    let fingerprint: Uint8Array | undefined;
    let frame: Uint8Array | undefined;
    try {
        peer = bytes(value.peer, "deferred invitation peer", 32, 32);
        const messageId = id(value.messageId, "deferred invitation message ID", 24);
        fingerprint = bytes(value.fingerprint, "deferred invitation fingerprint", 32, 32);
        frame = bytes(value.frame, "deferred invitation frame", 1024 * 1024);
        return { peer, messageId, fingerprint, frame };
    } catch (error: unknown) {
        peer?.fill(0);
        fingerprint?.fill(0);
        frame?.fill(0);
        throw error;
    }
}

/** Encode one durable group metadata record. */
export function encodeGroup(group: StoredGroup): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 1,
            id: group.id,
            descriptor: encodeBase64Url(group.descriptor),
            descriptorNonce: encodeBase64Url(group.descriptorNonce),
            descriptorBinding: encodeBase64Url(group.descriptorBinding),
            topicSecret: encodeBase64Url(group.topicSecret),
            members: group.members.map(encodeBase64Url),
            createdAt: group.createdAt,
            epoch: group.epoch.toString(),
            persistenceGeneration: group.persistenceGeneration.toString(),
            status: group.status,
        }),
    );
}

/** Decode one strict durable group metadata record. */
export function decodeGroup(encoded: Uint8Array): StoredGroup {
    const value = exactParsed(
        encoded,
        [
            "version",
            "id",
            "descriptor",
            "descriptorNonce",
            "descriptorBinding",
            "topicSecret",
            "members",
            "createdAt",
            "epoch",
            "persistenceGeneration",
            "status",
        ],
        "group record",
    );
    if (value.version !== 1 || (value.status !== "active" && value.status !== "removed")) {
        throw new Error("Invalid group record");
    }
    if (
        !Array.isArray(value.members) ||
        value.members.length === 0 ||
        value.members.length > 100_000
    ) {
        throw new Error("Invalid group members");
    }
    const members = value.members.map((member) => bytes(member, "group member identity", 32, 32));
    const memberIds = new Set(members.map(encodeBase64Url));
    if (memberIds.size !== members.length) {
        throw new Error("Invalid duplicate group member");
    }
    return {
        id: id(value.id, "group ID", 32),
        descriptor: bytes(value.descriptor, "group descriptor"),
        descriptorNonce: bytes(value.descriptorNonce, "group descriptor nonce", 32, 32),
        descriptorBinding: bytes(value.descriptorBinding, "group descriptor binding", 32, 32),
        topicSecret: bytes(value.topicSecret, "group topic secret", 32, 32),
        members,
        createdAt: integer(value.createdAt, "group creation time"),
        epoch: uint64(value.epoch, "group epoch"),
        persistenceGeneration: uint64(value.persistenceGeneration, "group persistence generation"),
        status: value.status,
    };
}

/** Encode one high-level group operation retained until relay-order resolution. */
export function encodeGroupOperation(operation: GroupOperation): Uint8Array {
    const attempt =
        operation.type === "send" && operation.attempt !== undefined
            ? {
                  eventId: operation.attempt.eventId,
                  fingerprint: encodeBase64Url(operation.attempt.fingerprint),
                  epoch: operation.attempt.epoch.toString(),
              }
            : null;
    return utf8Encode(
        JSON.stringify({
            version: 1,
            id: operation.id,
            type: operation.type,
            payload: operation.type === "send" ? encodeBase64Url(operation.payload) : null,
            peer: operation.type === "send" ? null : encodeBase64Url(operation.peer),
            createdAt: operation.createdAt,
            attempt,
        }),
    );
}

/** Decode one high-level group operation. */
export function decodeGroupOperation(encoded: Uint8Array): GroupOperation {
    const value = exactParsed(
        encoded,
        ["version", "id", "type", "payload", "peer", "createdAt", "attempt"],
        "group operation",
    );
    if (
        value.version !== 1 ||
        (value.type !== "send" && value.type !== "add" && value.type !== "remove")
    ) {
        throw new Error("Invalid group operation");
    }
    const common = {
        id: id(value.id, "group operation ID", 24),
        createdAt: integer(value.createdAt, "group operation time"),
    };
    if (value.type !== "send") {
        if (value.payload !== null || value.attempt !== null) {
            throw new Error("Invalid membership operation");
        }
        return {
            ...common,
            type: value.type,
            peer: bytes(value.peer, "group operation peer", 32, 32),
        };
    }
    if (value.peer !== null) {
        throw new Error("Invalid send operation");
    }
    let attempt: GroupOperationAttempt | undefined;
    if (value.attempt !== null) {
        const stored = object(
            value.attempt,
            ["eventId", "fingerprint", "epoch"],
            "group operation attempt",
        );
        attempt = {
            eventId: id(stored.eventId, "relay event ID", 32),
            fingerprint: bytes(stored.fingerprint, "group attempt fingerprint", 32, 32),
            epoch: uint64(stored.epoch, "group attempt epoch"),
        };
    }
    return {
        ...common,
        type: "send",
        payload: bytes(value.payload, "group operation payload"),
        ...(attempt === undefined ? {} : { attempt }),
    };
}

/** Encode one separately staged next-epoch membership candidate. */
export function encodeStagedCommit(staged: StagedGroupCommit): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 1,
            operationId: staged.operationId,
            eventId: staged.eventId,
            fingerprint: encodeBase64Url(staged.fingerprint),
            currentEpoch: staged.currentEpoch.toString(),
            currentGeneration: staged.currentGeneration.toString(),
            nextEpoch: encodeBase64Url(staged.nextEpoch),
            type: staged.type,
            peer: encodeBase64Url(staged.peer),
            keyPackageReference:
                staged.keyPackageReference === undefined
                    ? null
                    : encodeBase64Url(staged.keyPackageReference),
            welcome: staged.welcome === undefined ? null : encodeBase64Url(staged.welcome),
            tree: staged.tree === undefined ? null : encodeBase64Url(staged.tree),
        }),
    );
}

/** Decode one separately staged next-epoch membership candidate. */
export function decodeStagedCommit(encoded: Uint8Array): StagedGroupCommit {
    const value = exactParsed(
        encoded,
        [
            "version",
            "operationId",
            "eventId",
            "fingerprint",
            "currentEpoch",
            "currentGeneration",
            "nextEpoch",
            "type",
            "peer",
            "keyPackageReference",
            "welcome",
            "tree",
        ],
        "staged group Commit",
    );
    if (value.version !== 1 || (value.type !== "add" && value.type !== "remove")) {
        throw new Error("Invalid staged group Commit");
    }
    let keyPackageReference: Uint8Array | undefined;
    let welcome: Uint8Array | undefined;
    let tree: Uint8Array | undefined;
    let fingerprint: Uint8Array | undefined;
    let nextEpoch: Uint8Array | undefined;
    let peer: Uint8Array | undefined;
    try {
        keyPackageReference = nullableBytes(
            value.keyPackageReference,
            "staged KeyPackage reference",
            32,
            32,
        );
        welcome = nullableBytes(value.welcome, "staged Welcome", 16 * 1024 * 1024);
        tree = nullableBytes(value.tree, "staged ratchet tree", 16 * 1024 * 1024);
        if (
            (value.type === "add" &&
                (keyPackageReference === undefined ||
                    welcome === undefined ||
                    tree === undefined)) ||
            (value.type === "remove" &&
                (keyPackageReference !== undefined || welcome !== undefined || tree !== undefined))
        ) {
            throw new Error("Invalid staged group Commit material");
        }
        const operationId = id(value.operationId, "group operation ID", 24);
        const eventId = id(value.eventId, "relay event ID", 32);
        fingerprint = bytes(value.fingerprint, "Commit fingerprint", 32, 32);
        const currentEpoch = uint64(value.currentEpoch, "staged current epoch");
        const currentGeneration = uint64(
            value.currentGeneration,
            "staged current persistence generation",
        );
        nextEpoch = bytes(value.nextEpoch, "staged next epoch", 64 * 1024 * 1024);
        peer = bytes(value.peer, "staged peer", 32, 32);
        return {
            operationId,
            eventId,
            fingerprint,
            currentEpoch,
            currentGeneration,
            nextEpoch,
            type: value.type,
            peer,
            ...(keyPackageReference === undefined ? {} : { keyPackageReference }),
            ...(welcome === undefined ? {} : { welcome }),
            ...(tree === undefined ? {} : { tree }),
        };
    } catch (error: unknown) {
        keyPackageReference?.fill(0);
        welcome?.fill(0);
        tree?.fill(0);
        fingerprint?.fill(0);
        nextEpoch?.fill(0);
        peer?.fill(0);
        throw error;
    }
}

/** Encode one authenticated retained group application event. */
export function encodeGroupEvent(event: StoredGroupEvent): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 1,
            sequence: event.sequence.toString(),
            sender: encodeBase64Url(event.sender),
            bytes: encodeBase64Url(event.bytes),
        }),
    );
}

/** Decode one authenticated retained group application event. */
export function decodeGroupEvent(encoded: Uint8Array): StoredGroupEvent {
    const value = exactParsed(encoded, ["version", "sequence", "sender", "bytes"], "group event");
    if (value.version !== 1) {
        throw new Error("Invalid group event");
    }
    return {
        sequence: uint64(value.sequence, "group event sequence"),
        sender: bytes(value.sender, "group event sender", 32, 32),
        bytes: bytes(value.bytes, "group event bytes"),
    };
}
