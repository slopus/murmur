import type { SignedDelivery } from "../../delivery/index.js";
import { parseSignedDelivery, signedDeliveryToJson } from "../../delivery/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    type JsonValue,
} from "../../utils/index.js";
import { decodeSessionRoles, encodeSessionRoles, type SessionRoles } from "./sessionFrames.js";

export interface SessionRecord {
    readonly version: 2;
    readonly status: "creating" | "pending" | "active" | "removed";
    readonly descriptor: Uint8Array;
    readonly epoch: Uint8Array;
    readonly generation: bigint;
    readonly bufferedEvents: number;
    readonly bufferedBytes: number;
    readonly stagedCommitId?: string;
    readonly previousEpoch?: Uint8Array;
    readonly previousGeneration?: bigint;
    readonly previousEpochExpiresAt?: number;
    readonly previousMessagesRemaining?: number;
    readonly roles: SessionRoles;
    readonly removalGenerations: readonly SessionRemovalGeneration[];
    readonly bootstrapEventId?: string;
    readonly bootstrapKeyPackageReference?: Uint8Array;
}

export interface SessionRemovalGeneration {
    readonly account: Uint8Array;
    readonly generation: number;
}

export interface SessionOutboxRecord {
    readonly version: 2;
    readonly kind: "application" | "commit" | "bootstrap";
    readonly order: string;
    readonly operationId: string;
    readonly sessionId: Uint8Array;
    readonly delivery: SignedDelivery;
    readonly applicationData?: Uint8Array;
    readonly stagedEpoch?: Uint8Array;
    readonly parentCommitId?: string;
    readonly retainPreviousEpoch?: boolean;
    readonly bootstrapDeliveryIds?: readonly string[];
    readonly roles?: SessionRoles;
}

/** One durable asynchronous membership or role mutation. */
export type SessionIntentRecord =
    | {
          readonly version: 1;
          readonly kind: "add";
          readonly sessionId: Uint8Array;
          readonly account: Uint8Array;
          readonly device: Uint8Array;
          readonly keyPackage: Uint8Array;
          readonly removalGeneration: number;
      }
    | {
          readonly version: 1;
          readonly kind: "remove" | "grant_admin" | "revoke_admin" | "leave";
          readonly sessionId: Uint8Array;
          readonly account: Uint8Array;
      }
    | {
          readonly version: 1;
          readonly kind: "set_policies";
          readonly sessionId: Uint8Array;
          readonly adminsAssignAdmins: boolean;
          readonly anyoneCanAddMembers: boolean;
      };

export interface BufferedEventRecord {
    readonly version: 1;
    readonly sender: Uint8Array;
    readonly bytes: Uint8Array;
}

const DELIVERY_ID = /^[A-Za-z0-9_-]{32}$/;

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function bytes(value: unknown, maximum: number, name: string): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((maximum * 4) / 3)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (decoded.length > maximum || encodeBase64Url(decoded) !== value) {
        throw new Error(`Invalid ${name}`);
    }
    return decoded;
}

function integer(value: unknown, maximum: number, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function json(bytesValue: Uint8Array, maximum: number, name: string): Record<string, unknown> {
    if (bytesValue.length < 1 || bytesValue.length > maximum) {
        throw new Error(`Invalid ${name}`);
    }
    try {
        return object(JSON.parse(utf8Decode(bytesValue)) as unknown, name);
    } catch {
        throw new Error(`Invalid ${name}`);
    }
}

export function encodeSessionRecord(record: SessionRecord): Uint8Array {
    const common = {
        version: 2,
        status: record.status,
        descriptor: encodeBase64Url(record.descriptor),
        epoch: encodeBase64Url(record.epoch),
        generation: record.generation.toString(),
        bufferedEvents: record.bufferedEvents,
        bufferedBytes: record.bufferedBytes,
        stagedCommitId: record.stagedCommitId ?? null,
        previousEpoch:
            record.previousEpoch === undefined ? null : encodeBase64Url(record.previousEpoch),
        previousGeneration: record.previousGeneration?.toString() ?? null,
        previousEpochExpiresAt: record.previousEpochExpiresAt ?? null,
        previousMessagesRemaining: record.previousMessagesRemaining ?? null,
    };
    const removalGenerations = [...record.removalGenerations]
        .map((value) => ({ account: encodeBase64Url(value.account), generation: value.generation }))
        .sort((left, right) => left.account.localeCompare(right.account));
    if (
        removalGenerations.some(
            (value, index) =>
                value.generation < 0 ||
                !Number.isSafeInteger(value.generation) ||
                (index > 0 && removalGenerations[index - 1]!.account === value.account),
        )
    ) {
        throw new Error("Invalid session removal generations");
    }
    return canonicalJsonBytes({
        ...common,
        roles: encodeBase64Url(encodeSessionRoles(record.roles)),
        removalGenerations,
        bootstrapEventId: record.bootstrapEventId ?? null,
        bootstrapKeyPackageReference:
            record.bootstrapKeyPackageReference === undefined
                ? null
                : encodeBase64Url(record.bootstrapKeyPackageReference),
    } as unknown as JsonValue);
}

export function decodeSessionRecord(value: Uint8Array): SessionRecord {
    const input = json(value, 70 * 1024 * 1024, "session record");
    exact(
        input,
        [
            "version",
            "status",
            "descriptor",
            "epoch",
            "generation",
            "bufferedEvents",
            "bufferedBytes",
            "stagedCommitId",
            "previousEpoch",
            "previousGeneration",
            "previousEpochExpiresAt",
            "previousMessagesRemaining",
            "roles",
            "removalGenerations",
            "bootstrapEventId",
            "bootstrapKeyPackageReference",
        ],
        "session record",
    );
    if (
        input.version !== 2 ||
        (input.status !== "creating" &&
            input.status !== "pending" &&
            input.status !== "active" &&
            input.status !== "removed") ||
        typeof input.generation !== "string" ||
        !/^(0|[1-9]\d*)$/.test(input.generation) ||
        (input.stagedCommitId !== null && typeof input.stagedCommitId !== "string") ||
        (input.previousEpoch === null) !== (input.previousGeneration === null) ||
        (input.previousEpoch === null) !== (input.previousEpochExpiresAt === null) ||
        (input.previousEpoch === null) !== (input.previousMessagesRemaining === null) ||
        (input.previousEpoch !== null && typeof input.previousEpoch !== "string") ||
        (input.previousGeneration !== null &&
            (typeof input.previousGeneration !== "string" ||
                !/^(0|[1-9]\d*)$/.test(input.previousGeneration))) ||
        typeof input.roles !== "string" ||
        !Array.isArray(input.removalGenerations) ||
        input.removalGenerations.length > 256 ||
        (input.bootstrapEventId !== null &&
            (typeof input.bootstrapEventId !== "string" || input.bootstrapEventId.length > 128)) ||
        (input.bootstrapKeyPackageReference !== null &&
            typeof input.bootstrapKeyPackageReference !== "string")
    ) {
        throw new Error("Invalid session record");
    }
    const removalGenerations: SessionRemovalGeneration[] = (
        input.removalGenerations as unknown[]
    ).map((value) => {
        const entry = object(value, "session removal generation");
        exact(entry, ["account", "generation"], "session removal generation");
        return {
            account: bytes(entry.account, 32, "removed account"),
            generation: integer(entry.generation, Number.MAX_SAFE_INTEGER, "removal generation"),
        };
    });
    const removalAccounts = removalGenerations.map((entry) => encodeBase64Url(entry.account));
    if (
        removalAccounts.some(
            (account, index) =>
                index > 0 && removalAccounts[index - 1]!.localeCompare(account) >= 0,
        )
    ) {
        throw new Error("Invalid session removal generations");
    }
    return {
        version: 2,
        status: input.status,
        descriptor: bytes(input.descriptor, 1024 * 1024, "session descriptor"),
        epoch: bytes(input.epoch, 64 * 1024 * 1024, "session epoch"),
        generation: BigInt(input.generation),
        bufferedEvents: integer(input.bufferedEvents, 100_000, "buffered event count"),
        bufferedBytes: integer(input.bufferedBytes, 1024 * 1024 * 1024, "buffered event bytes"),
        ...(input.stagedCommitId === null ? {} : { stagedCommitId: input.stagedCommitId }),
        ...(input.previousEpoch === null
            ? {}
            : {
                  previousEpoch: bytes(
                      input.previousEpoch,
                      64 * 1024 * 1024,
                      "previous session epoch",
                  ),
                  previousGeneration: BigInt(input.previousGeneration as string),
                  previousEpochExpiresAt: integer(
                      input.previousEpochExpiresAt,
                      Number.MAX_SAFE_INTEGER,
                      "previous epoch expiry",
                  ),
                  previousMessagesRemaining: integer(
                      input.previousMessagesRemaining,
                      1_000,
                      "previous epoch message count",
                  ),
              }),
        roles: decodeSessionRoles(bytes(input.roles, 64 * 1024, "session roles")),
        removalGenerations,
        ...(input.bootstrapEventId === null
            ? {}
            : { bootstrapEventId: input.bootstrapEventId as string }),
        ...(input.bootstrapKeyPackageReference === null
            ? {}
            : {
                  bootstrapKeyPackageReference: bytes(
                      input.bootstrapKeyPackageReference,
                      32,
                      "bootstrap KeyPackage reference",
                  ),
              }),
    };
}

export function encodeOutboxRecord(record: SessionOutboxRecord): Uint8Array {
    return canonicalJsonBytes({
        version: 2,
        kind: record.kind,
        order: record.order,
        operationId: record.operationId,
        sessionId: encodeBase64Url(record.sessionId),
        delivery: signedDeliveryToJson(record.delivery) as unknown as JsonValue,
        applicationData:
            record.applicationData === undefined ? null : encodeBase64Url(record.applicationData),
        stagedEpoch: record.stagedEpoch === undefined ? null : encodeBase64Url(record.stagedEpoch),
        parentCommitId: record.parentCommitId ?? null,
        retainPreviousEpoch: record.retainPreviousEpoch ?? null,
        bootstrapDeliveryIds: record.bootstrapDeliveryIds ?? null,
        roles:
            record.roles === undefined ? null : encodeBase64Url(encodeSessionRoles(record.roles)),
    });
}

export function decodeOutboxRecord(value: Uint8Array): SessionOutboxRecord {
    const input = json(value, 80 * 1024 * 1024, "session outbox");
    exact(
        input,
        [
            "version",
            "kind",
            "order",
            "operationId",
            "sessionId",
            "delivery",
            "applicationData",
            "stagedEpoch",
            "parentCommitId",
            "retainPreviousEpoch",
            "bootstrapDeliveryIds",
            "roles",
        ],
        "session outbox",
    );
    if (
        input.version !== 2 ||
        (input.kind !== "application" && input.kind !== "commit" && input.kind !== "bootstrap") ||
        typeof input.order !== "string" ||
        !/^\d{32}$/.test(input.order) ||
        typeof input.operationId !== "string" ||
        !DELIVERY_ID.test(input.operationId) ||
        (input.applicationData !== null && typeof input.applicationData !== "string") ||
        (input.stagedEpoch !== null && typeof input.stagedEpoch !== "string") ||
        (input.parentCommitId !== null &&
            (typeof input.parentCommitId !== "string" ||
                !DELIVERY_ID.test(input.parentCommitId))) ||
        (input.retainPreviousEpoch !== null && typeof input.retainPreviousEpoch !== "boolean") ||
        (input.bootstrapDeliveryIds !== null &&
            (!Array.isArray(input.bootstrapDeliveryIds) ||
                input.bootstrapDeliveryIds.length > 256 ||
                input.bootstrapDeliveryIds.some(
                    (value) => typeof value !== "string" || !DELIVERY_ID.test(value),
                ) ||
                new Set(input.bootstrapDeliveryIds).size !== input.bootstrapDeliveryIds.length)) ||
        (input.roles !== null && typeof input.roles !== "string")
    ) {
        throw new Error("Invalid session outbox");
    }
    const hasApplicationData = input.applicationData !== null;
    const hasStagedEpoch = input.stagedEpoch !== null;
    const hasParentCommit = input.parentCommitId !== null;
    const hasRetainPreviousEpoch = input.retainPreviousEpoch !== null;
    const hasBootstrapDeliveryIds = input.bootstrapDeliveryIds !== null;
    const hasRoles = input.roles !== null;
    if (
        (input.kind === "application" &&
            (!hasApplicationData ||
                hasStagedEpoch ||
                hasRoles ||
                hasRetainPreviousEpoch ||
                hasBootstrapDeliveryIds)) ||
        (input.kind === "commit" &&
            (hasApplicationData ||
                !hasStagedEpoch ||
                !hasRoles ||
                hasParentCommit ||
                !hasRetainPreviousEpoch ||
                !hasBootstrapDeliveryIds)) ||
        (input.kind === "bootstrap" &&
            (hasApplicationData ||
                hasStagedEpoch ||
                hasRoles ||
                !hasParentCommit ||
                hasRetainPreviousEpoch ||
                hasBootstrapDeliveryIds))
    ) {
        throw new Error("Invalid session outbox fields");
    }
    return {
        version: 2,
        kind: input.kind,
        order: input.order,
        operationId: input.operationId,
        sessionId: bytes(input.sessionId, 255, "outbox session ID"),
        delivery: parseSignedDelivery(input.delivery),
        ...(input.applicationData === null
            ? {}
            : { applicationData: bytes(input.applicationData, 1024 * 1024, "outbox data") }),
        ...(input.stagedEpoch === null
            ? {}
            : { stagedEpoch: bytes(input.stagedEpoch, 64 * 1024 * 1024, "staged epoch") }),
        ...(input.parentCommitId === null ? {} : { parentCommitId: input.parentCommitId }),
        ...(input.retainPreviousEpoch === null
            ? {}
            : { retainPreviousEpoch: input.retainPreviousEpoch }),
        ...(input.bootstrapDeliveryIds === null
            ? {}
            : { bootstrapDeliveryIds: input.bootstrapDeliveryIds as string[] }),
        ...(input.roles === null
            ? {}
            : { roles: decodeSessionRoles(bytes(input.roles, 64 * 1024, "outbox roles")) }),
    };
}

/** Strict durable encoding for one asynchronous session intent. */
export function encodeSessionIntent(record: SessionIntentRecord): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        kind: record.kind,
        sessionId: encodeBase64Url(record.sessionId),
        ...(record.kind === "set_policies"
            ? {
                  adminsAssignAdmins: record.adminsAssignAdmins,
                  anyoneCanAddMembers: record.anyoneCanAddMembers,
              }
            : { account: encodeBase64Url(record.account) }),
        ...(record.kind === "add"
            ? {
                  device: encodeBase64Url(record.device),
                  keyPackage: encodeBase64Url(record.keyPackage),
                  removalGeneration: record.removalGeneration,
              }
            : {}),
    } as unknown as JsonValue);
}

/** Strict durable decoder for one asynchronous session intent. */
export function decodeSessionIntent(value: Uint8Array): SessionIntentRecord {
    const input = json(value, 2 * 1024 * 1024, "session intent");
    if (
        input.version !== 1 ||
        (input.kind !== "add" &&
            input.kind !== "remove" &&
            input.kind !== "grant_admin" &&
            input.kind !== "revoke_admin" &&
            input.kind !== "set_policies" &&
            input.kind !== "leave")
    ) {
        throw new Error("Invalid session intent");
    }
    if (input.kind === "set_policies") {
        exact(
            input,
            ["version", "kind", "sessionId", "adminsAssignAdmins", "anyoneCanAddMembers"],
            "session intent",
        );
        if (
            typeof input.adminsAssignAdmins !== "boolean" ||
            typeof input.anyoneCanAddMembers !== "boolean"
        ) {
            throw new Error("Invalid session intent");
        }
        return {
            version: 1,
            kind: "set_policies",
            sessionId: bytes(input.sessionId, 255, "intent session ID"),
            adminsAssignAdmins: input.adminsAssignAdmins,
            anyoneCanAddMembers: input.anyoneCanAddMembers,
        };
    }
    const add = input.kind === "add";
    exact(
        input,
        [
            "version",
            "kind",
            "sessionId",
            "account",
            ...(add ? ["device", "keyPackage", "removalGeneration"] : []),
        ],
        "session intent",
    );
    const common = {
        version: 1 as const,
        sessionId: bytes(input.sessionId, 255, "intent session ID"),
        account: bytes(input.account, 32, "intent account"),
    };
    if (!add) {
        return {
            ...common,
            kind: input.kind as "remove" | "grant_admin" | "revoke_admin" | "leave",
        };
    }
    return {
        ...common,
        kind: "add",
        device: bytes(input.device, 32, "intent device"),
        keyPackage: bytes(input.keyPackage, 1024 * 1024, "intent KeyPackage"),
        removalGeneration: integer(
            input.removalGeneration,
            Number.MAX_SAFE_INTEGER,
            "intent removal generation",
        ),
    };
}

export function encodeBufferedEvent(record: BufferedEventRecord): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        sender: encodeBase64Url(record.sender),
        bytes: encodeBase64Url(record.bytes),
    });
}

export function decodeBufferedEvent(value: Uint8Array): BufferedEventRecord {
    const input = json(value, 2 * 1024 * 1024, "buffered session event");
    exact(input, ["version", "sender", "bytes"], "buffered session event");
    if (input.version !== 1) throw new Error("Invalid buffered session event");
    return {
        version: 1,
        sender: bytes(input.sender, 32, "buffered event sender"),
        bytes: bytes(input.bytes, 1024 * 1024, "buffered event bytes"),
    };
}
