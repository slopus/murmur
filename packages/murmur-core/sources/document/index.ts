import { equalBytes } from "../utils/index.js";
import {
    documentOperationIdKey,
    encodeDocumentOperation,
    validateDocumentOperation,
    validateDocumentOperationId,
} from "./impl/codec.js";
import type {
    AuthenticatedDocumentOperation,
    DocumentDeleteOperation,
    DocumentInsertOperation,
    DocumentOperation,
    DocumentOperationId,
} from "./types.js";

export type {
    AuthenticatedDocumentOperation,
    DocumentDeleteOperation,
    DocumentInsertOperation,
    DocumentOperation,
    DocumentOperationId,
} from "./types.js";
export {
    decodeDocumentOperation,
    documentOperationIdKey,
    encodeDocumentOperation,
} from "./impl/codec.js";

function copyId(id: DocumentOperationId): DocumentOperationId {
    return { actor: id.actor, sequence: id.sequence };
}

function copyOperation(operation: DocumentOperation): DocumentOperation {
    return operation.type === "insert"
        ? {
              version: 1,
              type: "insert",
              id: copyId(operation.id),
              after: operation.after === null ? null : copyId(operation.after),
              text: operation.text,
          }
        : {
              version: 1,
              type: "delete",
              id: copyId(operation.id),
              target: copyId(operation.target),
          };
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    const length = Math.min(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) {
            return difference;
        }
    }
    return left.length - right.length;
}

export const MAXIMUM_DOCUMENT_OPERATIONS = 10_000;
export const MAXIMUM_DOCUMENT_STATE_BYTES = 4 * 1024 * 1024;

/** Create a validated operation ID for one public identity and local sequence. */
export function createDocumentOperationId(actor: string, sequence: number): DocumentOperationId {
    return validateDocumentOperationId({ actor, sequence });
}

/** Create an insert operation. */
export function createDocumentInsert(
    id: DocumentOperationId,
    after: DocumentOperationId | null,
    text: string,
): DocumentInsertOperation {
    const operation = validateDocumentOperation({
        version: 1,
        type: "insert",
        id,
        after,
        text,
    });
    if (operation.type !== "insert") {
        throw new Error("Expected a document insert");
    }
    return operation;
}

/** Create a delete/tombstone operation. */
export function createDocumentDelete(
    id: DocumentOperationId,
    target: DocumentOperationId,
): DocumentDeleteOperation {
    const operation = validateDocumentOperation({
        version: 1,
        type: "delete",
        id,
        target,
    });
    if (operation.type !== "delete") {
        throw new Error("Expected a document delete");
    }
    return operation;
}

/**
 * Replicated growable-array text document.
 *
 * Operations are idempotent and commute. Inserts at the same anchor are sorted
 * by globally unique operation ID; deletes are permanent tombstones and may
 * arrive before their target.
 */
export class SharedTextDocument {
    readonly #operations = new Map<string, DocumentOperation>();
    readonly #encodedSizes = new Map<string, number>();
    readonly #inserts = new Map<string, DocumentInsertOperation>();
    readonly #tombstones = new Set<string>();
    #retainedBytes = 0;
    #greatestKey: string | undefined;

    /** Apply one local or remote operation under its authenticated MLS actor. */
    apply(operation: DocumentOperation, authenticatedActor: string): void {
        const validated = validateDocumentOperation(operation);
        const actor = validateDocumentOperationId({
            actor: authenticatedActor,
            sequence: 0,
        }).actor;
        if (validated.id.actor !== actor) {
            throw new Error("Document operation actor does not match authenticated sender");
        }
        const key = documentOperationIdKey(validated.id);
        const incomingBytes = encodeDocumentOperation(validated);
        const existing = this.#operations.get(key);
        if (existing !== undefined) {
            const existingBytes = encodeDocumentOperation(existing);
            if (equalBytes(existingBytes, incomingBytes)) {
                return;
            }
            const existingCost = this.#encodedSizes.get(key) ?? existingBytes.length;
            const observedCost = Math.max(existingCost, incomingBytes.length);
            this.#retainedBytes += observedCost - existingCost;
            this.#encodedSizes.set(key, observedCost);
            let changed = observedCost !== existingCost;
            if (compareBytes(incomingBytes, existingBytes) < 0) {
                this.#operations.set(key, copyOperation(validated));
                changed = true;
            }
            if (changed) {
                this.#trimToBudget();
                this.#rebuildIndexes();
            }
            return;
        }
        const hasCapacity =
            this.#operations.size < MAXIMUM_DOCUMENT_OPERATIONS &&
            this.#retainedBytes + incomingBytes.length <= MAXIMUM_DOCUMENT_STATE_BYTES;
        if (!hasCapacity && this.#greatestKey !== undefined && key >= this.#greatestKey) {
            return;
        }
        const copy = copyOperation(validated);
        this.#operations.set(key, copy);
        this.#encodedSizes.set(key, incomingBytes.length);
        this.#retainedBytes += incomingBytes.length;
        if (this.#greatestKey === undefined || key > this.#greatestKey) {
            this.#greatestKey = key;
        }
        if (!hasCapacity) {
            this.#trimToBudget();
            this.#rebuildIndexes();
            return;
        }
        if (copy.type === "insert") {
            this.#inserts.set(key, copy);
        } else {
            this.#tombstones.add(documentOperationIdKey(copy.target));
        }
    }

    /** Merge an operation collection in any delivery order. */
    merge(operations: Iterable<AuthenticatedDocumentOperation>): void {
        for (const entry of operations) {
            this.apply(entry.operation, entry.authenticatedActor);
        }
    }

    /** Deterministic visible text after all currently known operations. */
    render(): string {
        const children = new Map<string, DocumentInsertOperation[]>();
        for (const insert of this.#inserts.values()) {
            const anchor = insert.after === null ? "" : documentOperationIdKey(insert.after);
            const siblings = children.get(anchor) ?? [];
            siblings.push(insert);
            children.set(anchor, siblings);
        }
        for (const siblings of children.values()) {
            siblings.sort((left, right) => {
                const leftKey = documentOperationIdKey(left.id);
                const rightKey = documentOperationIdKey(right.id);
                return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
            });
        }

        const rendered: string[] = [];
        const visited = new Set<string>();
        const stack = [...(children.get("") ?? [])].reverse();
        while (stack.length > 0) {
            const insert = stack.pop();
            if (insert === undefined) {
                continue;
            }
            const key = documentOperationIdKey(insert.id);
            if (visited.has(key)) {
                continue;
            }
            visited.add(key);
            if (!this.#tombstones.has(key)) {
                rendered.push(insert.text);
            }
            const descendants = children.get(key) ?? [];
            for (let index = descendants.length - 1; index >= 0; index -= 1) {
                const descendant = descendants[index];
                if (descendant !== undefined) {
                    stack.push(descendant);
                }
            }
        }
        return rendered.join("");
    }

    /** Stable operation log suitable for persistence or catch-up transfer. */
    operations(): readonly DocumentOperation[] {
        return [...this.#operations]
            .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
            .map(([, operation]) => copyOperation(operation));
    }

    #rebuildIndexes(): void {
        this.#inserts.clear();
        this.#tombstones.clear();
        for (const [key, operation] of this.#operations) {
            if (operation.type === "insert") {
                this.#inserts.set(key, operation);
            } else {
                this.#tombstones.add(documentOperationIdKey(operation.target));
            }
        }
    }

    #trimToBudget(): void {
        while (
            this.#operations.size > MAXIMUM_DOCUMENT_OPERATIONS ||
            this.#retainedBytes > MAXIMUM_DOCUMENT_STATE_BYTES
        ) {
            const greatest = this.#greatestKey;
            if (greatest === undefined) {
                throw new Error("Shared-document budget accounting is inconsistent");
            }
            this.#operations.delete(greatest);
            this.#retainedBytes -= this.#encodedSizes.get(greatest) ?? 0;
            this.#encodedSizes.delete(greatest);
            this.#greatestKey = undefined;
            for (const key of this.#operations.keys()) {
                if (this.#greatestKey === undefined || key > this.#greatestKey) {
                    this.#greatestKey = key;
                }
            }
        }
    }
}
