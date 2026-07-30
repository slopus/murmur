import { createDocumentInsert, createDocumentOperationId, encodeBase64Url } from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import {
    applyCliDocumentOperation,
    nextCliDocumentOperationSequence,
    type CliDocumentRecord,
} from "../impl/documentCodec.js";

describe("CLI durable document state", () => {
    it("never reuses an actor sequence after the bounded CRDT drops an operation", () => {
        const actor = encodeBase64Url(new Uint8Array(32).fill(7));
        let record: CliDocumentRecord = {
            id: encodeBase64Url(new Uint8Array(16).fill(1)),
            groupId: encodeBase64Url(new Uint8Array(32).fill(2)),
            name: "Capacity",
            operations: [],
            actorHighWaterMarks: [],
        };

        for (let sequence = 1; sequence <= 75; sequence += 1) {
            const operation = createDocumentInsert(
                createDocumentOperationId(actor, sequence),
                null,
                "x".repeat(60 * 1024),
            );
            record = applyCliDocumentOperation(record, operation, actor);
        }

        expect(record.operations.length).toBeLessThan(75);
        expect(record.operations.some((operation) => operation.id.sequence === 75)).toBe(false);
        expect(record.actorHighWaterMarks).toEqual([{ actor, sequence: 75 }]);
        expect(nextCliDocumentOperationSequence(record, actor)).toBe(76);
    });
});
