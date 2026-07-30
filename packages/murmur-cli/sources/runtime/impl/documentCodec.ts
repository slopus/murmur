import {
    SharedTextDocument,
    decodeBase64Url,
    decodeDocumentOperation,
    encodeBase64Url,
    encodeDocumentOperation,
    equalBytes,
    utf8Decode,
    utf8Encode,
    type DocumentOperation,
    type DocumentOperationId,
} from "@slopus/murmur";

const MAXIMUM_DOCUMENT_NAME_BYTES = 128;
const MAXIMUM_DOCUMENT_RECORD_BYTES = 16 * 1024 * 1024;
const MAXIMUM_DOCUMENT_ACTORS = 100_000;

/** Durable convergent document state scoped to one CLI group. */
export interface CliDocumentRecord {
    readonly id: string;
    readonly groupId: string;
    readonly name: string;
    readonly operations: readonly DocumentOperation[];
    readonly actorHighWaterMarks: readonly DocumentOperationId[];
}

/** Authenticated MLS application payload for document creation or mutation. */
export interface CliDocumentApplication {
    readonly documentId: string;
    readonly name: string;
    readonly operation?: DocumentOperation;
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

function validateIdentifier(value: string, bytes: number, name: string): void {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = decodeBase64Url(value);
    if (decoded.length !== bytes || encodeBase64Url(decoded) !== value) {
        throw new Error(`Invalid ${name}`);
    }
}

function validateDocumentName(name: string): void {
    const bytes = utf8Encode(name);
    if (bytes.length === 0 || bytes.length > MAXIMUM_DOCUMENT_NAME_BYTES) {
        throw new Error("Invalid CLI document name");
    }
}

function canonicalOperations(
    operations: readonly DocumentOperation[],
): readonly DocumentOperation[] {
    const document = new SharedTextDocument();
    for (const operation of operations) {
        document.apply(operation, operation.id.actor);
    }
    const canonical = document.operations();
    if (
        canonical.length !== operations.length ||
        canonical.some(
            (operation, index) =>
                !equalBytes(
                    encodeDocumentOperation(operation),
                    encodeDocumentOperation(operations[index]!),
                ),
        )
    ) {
        throw new Error("Non-canonical CLI document operation log");
    }
    return canonical;
}

function canonicalHighWaterMarks(
    marks: readonly DocumentOperationId[],
    operations: readonly DocumentOperation[],
): readonly DocumentOperationId[] {
    if (marks.length > MAXIMUM_DOCUMENT_ACTORS) {
        throw new Error("Too many CLI document actors");
    }
    const actors = new Set<string>();
    let previous = "";
    for (const mark of marks) {
        validateIdentifier(mark.actor, 32, "CLI document actor");
        if (
            !Number.isSafeInteger(mark.sequence) ||
            mark.sequence < 0 ||
            mark.sequence > 0xffff_ffff ||
            mark.actor <= previous ||
            actors.has(mark.actor)
        ) {
            throw new Error("Invalid CLI document actor high-water marks");
        }
        actors.add(mark.actor);
        previous = mark.actor;
    }
    const byActor = new Map(marks.map((mark) => [mark.actor, mark.sequence]));
    if (
        operations.some(
            (operation) => (byActor.get(operation.id.actor) ?? -1) < operation.id.sequence,
        )
    ) {
        throw new Error("CLI document high-water mark trails its operation log");
    }
    return marks.map((mark) => ({ actor: mark.actor, sequence: mark.sequence }));
}

/** Encode one canonical durable shared-document operation log. */
export function encodeCliDocumentRecord(document: CliDocumentRecord): Uint8Array {
    validateIdentifier(document.id, 16, "CLI document ID");
    validateIdentifier(document.groupId, 32, "CLI document group ID");
    validateDocumentName(document.name);
    const operations = canonicalOperations(document.operations);
    const actorHighWaterMarks = canonicalHighWaterMarks(document.actorHighWaterMarks, operations);
    const encoded = utf8Encode(
        JSON.stringify({
            version: 1,
            id: document.id,
            groupId: document.groupId,
            name: document.name,
            actorHighWaterMarks,
            operations: operations.map((operation) =>
                encodeBase64Url(encodeDocumentOperation(operation)),
            ),
        }),
    );
    if (encoded.length > MAXIMUM_DOCUMENT_RECORD_BYTES) {
        throw new Error("CLI document record is too large");
    }
    return encoded;
}

/** Decode one canonical durable shared-document operation log. */
export function decodeCliDocumentRecord(bytes: Uint8Array): CliDocumentRecord {
    if (bytes.length > MAXIMUM_DOCUMENT_RECORD_BYTES) {
        throw new Error("CLI document record is too large");
    }
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "id", "groupId", "name", "actorHighWaterMarks", "operations"],
        "CLI document record",
    );
    if (
        value.version !== 1 ||
        typeof value.id !== "string" ||
        typeof value.groupId !== "string" ||
        typeof value.name !== "string" ||
        !Array.isArray(value.actorHighWaterMarks) ||
        value.actorHighWaterMarks.length > MAXIMUM_DOCUMENT_ACTORS ||
        !Array.isArray(value.operations) ||
        value.operations.length > 10_000 ||
        value.operations.some((operation) => typeof operation !== "string")
    ) {
        throw new Error("Invalid CLI document record");
    }
    const document: CliDocumentRecord = {
        id: value.id,
        groupId: value.groupId,
        name: value.name,
        actorHighWaterMarks: value.actorHighWaterMarks.map((mark) => {
            const decoded = record(
                mark,
                ["actor", "sequence"],
                "CLI document actor high-water mark",
            );
            if (typeof decoded.actor !== "string" || typeof decoded.sequence !== "number") {
                throw new Error("Invalid CLI document actor high-water mark");
            }
            return { actor: decoded.actor, sequence: decoded.sequence };
        }),
        operations: (value.operations as string[]).map((operation) =>
            decodeDocumentOperation(decodeBase64Url(operation)),
        ),
    };
    if (!equalBytes(encodeCliDocumentRecord(document), bytes)) {
        throw new Error("Non-canonical CLI document record");
    }
    return document;
}

/** Encode a document create/mutation as authenticated MLS application data. */
export function encodeCliDocumentApplication(application: CliDocumentApplication): Uint8Array {
    validateIdentifier(application.documentId, 16, "CLI document ID");
    validateDocumentName(application.name);
    return utf8Encode(
        JSON.stringify({
            kind: "murmur.document.v1",
            documentId: application.documentId,
            name: application.name,
            operation:
                application.operation === undefined
                    ? null
                    : encodeBase64Url(encodeDocumentOperation(application.operation)),
        }),
    );
}

/** Decode a document application, or return undefined for another group protocol. */
export function decodeCliDocumentApplication(
    bytes: Uint8Array,
): CliDocumentApplication | undefined {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch {
        return undefined;
    }
    if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed) ||
        (parsed as Record<string, unknown>).kind !== "murmur.document.v1"
    ) {
        return undefined;
    }
    const value = record(
        parsed,
        ["kind", "documentId", "name", "operation"],
        "CLI document application",
    );
    if (
        typeof value.documentId !== "string" ||
        typeof value.name !== "string" ||
        (value.operation !== null && typeof value.operation !== "string")
    ) {
        throw new Error("Invalid CLI document application");
    }
    const application: CliDocumentApplication = {
        documentId: value.documentId,
        name: value.name,
        ...(typeof value.operation === "string"
            ? {
                  operation: decodeDocumentOperation(decodeBase64Url(value.operation)),
              }
            : {}),
    };
    if (!equalBytes(encodeCliDocumentApplication(application), bytes)) {
        throw new Error("Non-canonical CLI document application");
    }
    return application;
}

/** Reconstruct the deterministic in-memory CRDT from a durable record. */
export function openCliDocument(record: CliDocumentRecord): SharedTextDocument {
    const document = new SharedTextDocument();
    for (const operation of record.operations) {
        document.apply(operation, operation.id.actor);
    }
    return document;
}

/** Apply one authenticated operation while advancing its durable actor high-water mark. */
export function applyCliDocumentOperation(
    record: CliDocumentRecord,
    operation: DocumentOperation,
    authenticatedActor: string,
): CliDocumentRecord {
    const document = openCliDocument(record);
    document.apply(operation, authenticatedActor);
    const marks = new Map(record.actorHighWaterMarks.map((mark) => [mark.actor, mark.sequence]));
    if (!marks.has(operation.id.actor) && marks.size >= MAXIMUM_DOCUMENT_ACTORS) {
        throw new Error("Too many CLI document actors");
    }
    marks.set(
        operation.id.actor,
        Math.max(marks.get(operation.id.actor) ?? 0, operation.id.sequence),
    );
    return {
        ...record,
        operations: document.operations(),
        actorHighWaterMarks: [...marks]
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .map(([actor, sequence]) => ({ actor, sequence })),
    };
}

/** Allocate the next never-reused local operation sequence for one document actor. */
export function nextCliDocumentOperationSequence(record: CliDocumentRecord, actor: string): number {
    validateIdentifier(actor, 32, "CLI document actor");
    const current = record.actorHighWaterMarks.find((mark) => mark.actor === actor)?.sequence ?? 0;
    if (current >= 0xffff_ffff) {
        throw new Error("Document operation sequence is exhausted");
    }
    return current + 1;
}
