/** HTTP statuses used for expected, machine-readable relay failures. */
export type RelayErrorStatus = 400 | 401 | 404 | 409 | 413 | 429 | 503;

/** Expected relay failure which can cross the Fetch boundary without becoming a 500. */
export class RelayError extends Error {
    readonly status: RelayErrorStatus;
    readonly body: Readonly<Record<string, unknown>>;

    constructor(
        status: RelayErrorStatus,
        message: string,
        body: Readonly<Record<string, unknown>> = { error: message },
    ) {
        super(message);
        this.name = "RelayError";
        this.status = status;
        this.body = body;
    }
}

/** Optimistic-concurrency failure with every touched element's current version. */
export class RelayConflictError extends RelayError {
    readonly snapshotVersion: bigint;
    readonly elements: Readonly<Record<string, bigint>>;

    constructor(snapshotVersion: bigint, elements: Readonly<Record<string, bigint>>) {
        super(409, "Relay state conflict", {
            error: "conflict",
            snapshotVersion,
            elements,
        });
        this.name = "RelayConflictError";
        this.snapshotVersion = snapshotVersion;
        this.elements = elements;
    }
}
