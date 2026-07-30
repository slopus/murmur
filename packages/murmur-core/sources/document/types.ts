/** Globally unique operation identifier scoped to one public-key actor. */
export interface DocumentOperationId {
    readonly actor: string;
    readonly sequence: number;
}

/** Insert one immutable text span after another span, or at the document root. */
export interface DocumentInsertOperation {
    readonly version: 1;
    readonly type: "insert";
    readonly id: DocumentOperationId;
    readonly after: DocumentOperationId | null;
    readonly text: string;
}

/** Tombstone one previously inserted span. */
export interface DocumentDeleteOperation {
    readonly version: 1;
    readonly type: "delete";
    readonly id: DocumentOperationId;
    readonly target: DocumentOperationId;
}

/** Commutative operation carried as encrypted group application data. */
export type DocumentOperation = DocumentInsertOperation | DocumentDeleteOperation;

/** Operation paired with the public-key actor authenticated by the group layer. */
export interface AuthenticatedDocumentOperation {
    readonly operation: DocumentOperation;
    readonly authenticatedActor: string;
}
