import type { SignedDelivery } from "../../delivery/index.js";
import { parseSignedDelivery, signedDeliveryToJson } from "../../delivery/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    type JsonValue,
} from "../../utils/index.js";

export interface SessionRecord {
    readonly version: 1;
    readonly status: "creating" | "pending" | "active" | "removed";
    readonly descriptor: Uint8Array;
    readonly committer: Uint8Array;
    readonly epoch: Uint8Array;
    readonly generation: bigint;
    readonly bufferedEvents: number;
    readonly bufferedBytes: number;
    readonly stagedCommitId?: string;
    readonly previousEpoch?: Uint8Array;
    readonly previousGeneration?: bigint;
    readonly previousEpochExpiresAt?: number;
    readonly previousMessagesRemaining?: number;
}

export interface SessionOutboxRecord {
    readonly version: 1;
    readonly kind: "application" | "proposal" | "commit" | "bootstrap";
    readonly order: string;
    readonly operationId: string;
    readonly sessionId: Uint8Array;
    readonly delivery: SignedDelivery;
    readonly applicationData?: Uint8Array;
    readonly stagedEpoch?: Uint8Array;
    readonly nextCommitter?: Uint8Array;
    readonly parentCommitId?: string;
    readonly retainPreviousEpoch?: boolean;
    readonly consumedProposalKeys?: readonly string[];
    readonly bootstrapDeliveryIds?: readonly string[];
}

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
    return canonicalJsonBytes({
        version: 1,
        status: record.status,
        descriptor: encodeBase64Url(record.descriptor),
        committer: encodeBase64Url(record.committer),
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
            "committer",
            "epoch",
            "generation",
            "bufferedEvents",
            "bufferedBytes",
            "stagedCommitId",
            "previousEpoch",
            "previousGeneration",
            "previousEpochExpiresAt",
            "previousMessagesRemaining",
        ],
        "session record",
    );
    if (
        input.version !== 1 ||
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
                !/^(0|[1-9]\d*)$/.test(input.previousGeneration)))
    ) {
        throw new Error("Invalid session record");
    }
    return {
        version: 1,
        status: input.status,
        descriptor: bytes(input.descriptor, 1024 * 1024, "session descriptor"),
        committer: bytes(input.committer, 32, "session committer"),
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
    };
}

export function encodeOutboxRecord(record: SessionOutboxRecord): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        kind: record.kind,
        order: record.order,
        operationId: record.operationId,
        sessionId: encodeBase64Url(record.sessionId),
        delivery: signedDeliveryToJson(record.delivery) as unknown as JsonValue,
        applicationData:
            record.applicationData === undefined ? null : encodeBase64Url(record.applicationData),
        stagedEpoch: record.stagedEpoch === undefined ? null : encodeBase64Url(record.stagedEpoch),
        nextCommitter:
            record.nextCommitter === undefined ? null : encodeBase64Url(record.nextCommitter),
        parentCommitId: record.parentCommitId ?? null,
        retainPreviousEpoch: record.retainPreviousEpoch ?? null,
        consumedProposalKeys: record.consumedProposalKeys ?? null,
        bootstrapDeliveryIds: record.bootstrapDeliveryIds ?? null,
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
            "nextCommitter",
            "parentCommitId",
            "retainPreviousEpoch",
            "consumedProposalKeys",
            "bootstrapDeliveryIds",
        ],
        "session outbox",
    );
    if (
        input.version !== 1 ||
        (input.kind !== "application" &&
            input.kind !== "proposal" &&
            input.kind !== "commit" &&
            input.kind !== "bootstrap") ||
        typeof input.order !== "string" ||
        !/^\d{32}$/.test(input.order) ||
        typeof input.operationId !== "string" ||
        !DELIVERY_ID.test(input.operationId) ||
        (input.applicationData !== null && typeof input.applicationData !== "string") ||
        (input.stagedEpoch !== null && typeof input.stagedEpoch !== "string") ||
        (input.nextCommitter !== null && typeof input.nextCommitter !== "string") ||
        (input.parentCommitId !== null &&
            (typeof input.parentCommitId !== "string" ||
                !DELIVERY_ID.test(input.parentCommitId))) ||
        (input.retainPreviousEpoch !== null && typeof input.retainPreviousEpoch !== "boolean") ||
        (input.consumedProposalKeys !== null &&
            (!Array.isArray(input.consumedProposalKeys) ||
                input.consumedProposalKeys.length > 64 ||
                input.consumedProposalKeys.some(
                    (value) =>
                        typeof value !== "string" ||
                        value.length > 512 ||
                        !value.startsWith("murmur/session-data/"),
                ) ||
                new Set(input.consumedProposalKeys).size !== input.consumedProposalKeys.length)) ||
        (input.bootstrapDeliveryIds !== null &&
            (!Array.isArray(input.bootstrapDeliveryIds) ||
                input.bootstrapDeliveryIds.length > 256 ||
                input.bootstrapDeliveryIds.some(
                    (value) => typeof value !== "string" || !DELIVERY_ID.test(value),
                ) ||
                new Set(input.bootstrapDeliveryIds).size !== input.bootstrapDeliveryIds.length))
    ) {
        throw new Error("Invalid session outbox");
    }
    const hasApplicationData = input.applicationData !== null;
    const hasStagedEpoch = input.stagedEpoch !== null;
    const hasNextCommitter = input.nextCommitter !== null;
    const hasParentCommit = input.parentCommitId !== null;
    const hasRetainPreviousEpoch = input.retainPreviousEpoch !== null;
    const hasConsumedProposalKeys = input.consumedProposalKeys !== null;
    const hasBootstrapDeliveryIds = input.bootstrapDeliveryIds !== null;
    if (
        (input.kind === "application" &&
            (!hasApplicationData ||
                hasStagedEpoch ||
                hasNextCommitter ||
                hasRetainPreviousEpoch ||
                hasConsumedProposalKeys ||
                hasBootstrapDeliveryIds)) ||
        (input.kind === "proposal" &&
            (!hasApplicationData ||
                hasStagedEpoch ||
                hasNextCommitter ||
                hasParentCommit ||
                hasRetainPreviousEpoch ||
                hasConsumedProposalKeys ||
                hasBootstrapDeliveryIds)) ||
        (input.kind === "commit" &&
            (hasApplicationData ||
                !hasStagedEpoch ||
                !hasNextCommitter ||
                hasParentCommit ||
                !hasRetainPreviousEpoch ||
                !hasConsumedProposalKeys ||
                !hasBootstrapDeliveryIds)) ||
        (input.kind === "bootstrap" &&
            (hasApplicationData ||
                hasStagedEpoch ||
                hasNextCommitter ||
                !hasParentCommit ||
                hasRetainPreviousEpoch ||
                hasConsumedProposalKeys ||
                hasBootstrapDeliveryIds))
    ) {
        throw new Error("Invalid session outbox fields");
    }
    return {
        version: 1,
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
        ...(input.nextCommitter === null
            ? {}
            : { nextCommitter: bytes(input.nextCommitter, 32, "next committer") }),
        ...(input.parentCommitId === null ? {} : { parentCommitId: input.parentCommitId }),
        ...(input.retainPreviousEpoch === null
            ? {}
            : { retainPreviousEpoch: input.retainPreviousEpoch }),
        ...(input.consumedProposalKeys === null
            ? {}
            : { consumedProposalKeys: input.consumedProposalKeys as string[] }),
        ...(input.bootstrapDeliveryIds === null
            ? {}
            : { bootstrapDeliveryIds: input.bootstrapDeliveryIds as string[] }),
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
