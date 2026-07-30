import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type { DocumentOperation, DocumentOperationId } from "../types.js";

export const MAXIMUM_DOCUMENT_OPERATION_BYTES = 1024 * 1024;
export const MAXIMUM_DOCUMENT_SPAN_BYTES = 64 * 1024;
const MAXIMUM_SEQUENCE = 0xffff_ffff;

function object(value: unknown, name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exactFields(
    value: Record<string, unknown>,
    fields: readonly string[],
    name: string,
): void {
    const allowed = new Set(fields);
    if (
        Object.keys(value).length !== fields.length ||
        Object.keys(value).some((field) => !allowed.has(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

/** Validate and canonicalize one document operation ID. */
export function validateDocumentOperationId(value: unknown): DocumentOperationId {
    const id = object(value, "document operation ID");
    exactFields(id, ["actor", "sequence"], "document operation ID");
    if (
        typeof id.actor !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(id.actor) ||
        typeof id.sequence !== "number" ||
        !Number.isSafeInteger(id.sequence) ||
        id.sequence < 0 ||
        id.sequence > MAXIMUM_SEQUENCE
    ) {
        throw new Error("Invalid document operation ID");
    }
    const actorBytes = decodeBase64Url(id.actor);
    if (actorBytes.length !== 32 || encodeBase64Url(actorBytes) !== id.actor) {
        throw new Error("Invalid document operation actor");
    }
    return { actor: id.actor, sequence: id.sequence };
}

/** Stable string key for maps and deterministic sibling ordering. */
export function documentOperationIdKey(id: DocumentOperationId): string {
    const validated = validateDocumentOperationId(id);
    return `${validated.actor}:${validated.sequence.toString(16).padStart(8, "0")}`;
}

/** Validate and copy one decoded document operation. */
export function validateDocumentOperation(value: unknown): DocumentOperation {
    const operation = object(value, "document operation");
    if (operation.version !== 1 || (operation.type !== "insert" && operation.type !== "delete")) {
        throw new Error("Invalid document operation");
    }
    if (operation.type === "insert") {
        exactFields(operation, ["version", "type", "id", "after", "text"], "document insert");
        if (
            typeof operation.text !== "string" ||
            utf8Encode(operation.text).length > MAXIMUM_DOCUMENT_SPAN_BYTES
        ) {
            throw new Error("Invalid document insert text");
        }
        const id = validateDocumentOperationId(operation.id);
        const after =
            operation.after === null ? null : validateDocumentOperationId(operation.after);
        if (after !== null && documentOperationIdKey(after) === documentOperationIdKey(id)) {
            throw new Error("A document insert cannot reference itself");
        }
        return { version: 1, type: "insert", id, after, text: operation.text };
    }
    exactFields(operation, ["version", "type", "id", "target"], "document delete");
    return {
        version: 1,
        type: "delete",
        id: validateDocumentOperationId(operation.id),
        target: validateDocumentOperationId(operation.target),
    };
}

/** Encode one operation as strict UTF-8 JSON application data. */
export function encodeDocumentOperation(operation: DocumentOperation): Uint8Array {
    const validated = validateDocumentOperation(operation);
    const bytes = utf8Encode(JSON.stringify(validated));
    if (bytes.length > MAXIMUM_DOCUMENT_OPERATION_BYTES) {
        throw new Error("Document operation is too large");
    }
    return bytes;
}

/** Decode one strict UTF-8 JSON application operation. */
export function decodeDocumentOperation(bytes: Uint8Array): DocumentOperation {
    if (bytes.length > MAXIMUM_DOCUMENT_OPERATION_BYTES) {
        throw new Error("Document operation is too large");
    }
    return validateDocumentOperation(JSON.parse(utf8Decode(bytes)));
}
