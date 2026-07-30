import { encodeBase64Url, utf8Encode } from "../../utils/index.js";
import { describe, expect, it } from "vitest";
import {
    createDocumentDelete,
    createDocumentInsert,
    createDocumentOperationId,
    decodeDocumentOperation,
    encodeDocumentOperation,
    MAXIMUM_DOCUMENT_OPERATIONS,
    MAXIMUM_DOCUMENT_STATE_BYTES,
    SharedTextDocument,
    type DocumentOperationId,
} from "../index.js";

const alice = encodeBase64Url(new Uint8Array(32).fill(1));
const bob = encodeBase64Url(new Uint8Array(32).fill(2));

function authenticated<T extends { readonly id: { readonly actor: string } }>(
    operation: T,
): { readonly operation: T; readonly authenticatedActor: string } {
    return { operation, authenticatedActor: operation.id.actor };
}

describe("SharedTextDocument", () => {
    it("converges under concurrent and out-of-order operations", () => {
        const aliceInsert = createDocumentInsert(createDocumentOperationId(alice, 1), null, "A");
        const bobInsert = createDocumentInsert(createDocumentOperationId(bob, 1), null, "B");
        const afterAlice = createDocumentInsert(
            createDocumentOperationId(bob, 2),
            aliceInsert.id,
            "!",
        );
        const deleteAlice = createDocumentDelete(
            createDocumentOperationId(alice, 2),
            aliceInsert.id,
        );
        const left = new SharedTextDocument();
        const right = new SharedTextDocument();

        left.merge([aliceInsert, bobInsert, afterAlice, deleteAlice].map(authenticated));
        right.merge([deleteAlice, afterAlice, bobInsert, aliceInsert].map(authenticated));

        expect(left.render()).toBe(right.render());
        expect(left.render()).toContain("!");
        expect(left.render()).not.toContain("A");
        expect(left.operations()).toEqual(right.operations());
    });

    it("is idempotent and resolves collisions independently of arrival order", () => {
        const id = createDocumentOperationId(alice, 1);
        const first = createDocumentInsert(id, null, "same");
        const second = createDocumentInsert(id, null, "different");
        const left = new SharedTextDocument();
        const right = new SharedTextDocument();

        left.apply(first, alice);
        left.apply(second, alice);
        right.apply(second, alice);
        right.apply(first, alice);
        const retained = left.operations()[0];
        if (retained === undefined) {
            throw new Error("Expected one retained operation");
        }
        left.apply(decodeDocumentOperation(encodeDocumentOperation(retained)), alice);

        expect(left.operations()).toEqual(right.operations());
        expect(left.render()).toBe(right.render());
    });

    it("binds authors and enforces a deterministic aggregate quota", () => {
        const span = "x".repeat(60 * 1024);
        const operationCount =
            Math.ceil(MAXIMUM_DOCUMENT_STATE_BYTES / utf8Encode(span).length) + 4;
        const operations = Array.from({ length: operationCount }, (_, index) =>
            createDocumentInsert(createDocumentOperationId(alice, index + 1), null, span),
        );
        const left = new SharedTextDocument();
        const right = new SharedTextDocument();

        left.merge(operations.map(authenticated));
        right.merge([...operations].reverse().map(authenticated));

        expect(left.operations()).toEqual(right.operations());
        expect(left.operations().length).toBeLessThan(operations.length);
        const firstOperation = operations[0];
        if (firstOperation === undefined) {
            throw new Error("Expected a document operation");
        }
        expect(() => left.apply(firstOperation, bob)).toThrow("authenticated");
    });

    it("does not reopen quota after a shorter collision winner arrives", () => {
        const collisionId = createDocumentOperationId(alice, 1);
        const shorterWinner = createDocumentInsert(collisionId, null, "a");
        const longerLoser = createDocumentInsert(collisionId, null, "z".repeat(60 * 1024));
        const fillerCount = Math.ceil(MAXIMUM_DOCUMENT_STATE_BYTES / (60 * 1024)) + 3;
        const fillers = Array.from({ length: fillerCount }, (_, index) =>
            createDocumentInsert(
                createDocumentOperationId(alice, index + 2),
                null,
                "x".repeat(60 * 1024),
            ),
        );
        const left = new SharedTextDocument();
        const right = new SharedTextDocument();

        left.apply(longerLoser, alice);
        left.merge(fillers.map(authenticated));
        left.apply(shorterWinner, alice);
        right.apply(shorterWinner, alice);
        right.apply(longerLoser, alice);
        right.merge([...fillers].reverse().map(authenticated));

        expect(left.operations()).toEqual(right.operations());
        expect(left.render()).toBe(right.render());
    });

    it("renders a deep valid chain without recursive stack growth", () => {
        const document = new SharedTextDocument();
        let after: DocumentOperationId | null = null;
        for (let sequence = 1; sequence <= MAXIMUM_DOCUMENT_OPERATIONS; sequence += 1) {
            const insert = createDocumentInsert(
                createDocumentOperationId(alice, sequence),
                after,
                "x",
            );
            document.apply(insert, alice);
            after = insert.id;
        }

        expect(document.render()).toHaveLength(MAXIMUM_DOCUMENT_OPERATIONS);
    });

    it("rejects extra fields and oversized spans", () => {
        expect(() =>
            decodeDocumentOperation(
                utf8Encode(
                    JSON.stringify({
                        version: 1,
                        type: "insert",
                        id: { actor: alice, sequence: 1 },
                        after: null,
                        text: "x",
                        extra: true,
                    }),
                ),
            ),
        ).toThrow("insert");
        expect(() =>
            createDocumentInsert(
                createDocumentOperationId(alice, 1),
                null,
                "x".repeat(64 * 1024 + 1),
            ),
        ).toThrow("text");
    });
});
