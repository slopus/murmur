/** HTTP statuses used for expected, machine-readable relay failures. */
export type RelayErrorStatus = 400 | 401 | 403 | 404 | 409 | 413 | 429 | 503;

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
