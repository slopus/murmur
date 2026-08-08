import type { Pool, PoolClient } from "pg";

/** Values deliberately supported by relay SQL adapters. Bigints cross as strings. */
export type PostgresParameter = string | number | Uint8Array | null;

/** Small database query seam shared by pg and PGlite. */
export interface PostgresQuery {
    query<Row extends Record<string, unknown>>(
        text: string,
        values?: readonly PostgresParameter[],
    ): Promise<{ readonly rows: readonly Row[] }>;
}

/** One dedicated database session which can host transactions and advisory locks. */
export interface PostgresSession extends PostgresQuery {
    transaction<Result>(
        operation: (transaction: PostgresQuery) => Promise<Result>,
        isolation?: "read committed" | "repeatable read",
    ): Promise<Result>;
}

/** Database adapter required by the Postgres relay store. */
export interface PostgresDatabase extends PostgresSession {
    connection<Result>(
        operation: (connection: PostgresSession) => Promise<Result>,
    ): Promise<Result>;
    close(): Promise<void>;
}

function parameters(
    values: readonly PostgresParameter[] | undefined,
): PostgresParameter[] | undefined {
    return values === undefined ? undefined : [...values];
}

class PoolSession implements PostgresSession {
    readonly #client: PoolClient;

    constructor(client: PoolClient) {
        this.#client = client;
    }

    async query<Row extends Record<string, unknown>>(
        text: string,
        values?: readonly PostgresParameter[],
    ): Promise<{ readonly rows: readonly Row[] }> {
        const result = await this.#client.query<Row>(text, parameters(values));
        return { rows: result.rows };
    }

    async transaction<Result>(
        operation: (transaction: PostgresQuery) => Promise<Result>,
        isolation: "read committed" | "repeatable read" = "read committed",
    ): Promise<Result> {
        await this.#client.query(
            isolation === "repeatable read" ? "BEGIN ISOLATION LEVEL REPEATABLE READ" : "BEGIN",
        );
        try {
            const result = await operation(this);
            await this.#client.query("COMMIT");
            return result;
        } catch (error) {
            try {
                await this.#client.query("ROLLBACK");
            } catch {
                // Preserve the transaction's original error.
            }
            throw error;
        }
    }
}

/** Adapt a pg Pool to the minimal transaction interface used by the store. */
export class PgPoolDatabase implements PostgresDatabase {
    readonly #pool: Pool;
    #closed = false;

    constructor(pool: Pool) {
        this.#pool = pool;
    }

    /** Run one query using an arbitrary pooled connection. */
    async query<Row extends Record<string, unknown>>(
        text: string,
        values?: readonly PostgresParameter[],
    ): Promise<{ readonly rows: readonly Row[] }> {
        const result = await this.#pool.query<Row>(text, parameters(values));
        return { rows: result.rows };
    }

    /** Run an atomic operation on one leased pg connection. */
    async transaction<Result>(
        operation: (transaction: PostgresQuery) => Promise<Result>,
        isolation: "read committed" | "repeatable read" = "read committed",
    ): Promise<Result> {
        return this.connection((session) => session.transaction(operation, isolation));
    }

    /** Lease one stable pg session, including for session-level advisory locks. */
    async connection<Result>(
        operation: (connection: PostgresSession) => Promise<Result>,
    ): Promise<Result> {
        const client = await this.#pool.connect();
        try {
            return await operation(new PoolSession(client));
        } finally {
            client.release();
        }
    }

    /** End the owned pg pool once all relay work has stopped. */
    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            await this.#pool.end();
        }
    }
}

/** PGlite query surface used by the thin conformance adapter. */
export interface PGliteQueryLike {
    query<Row>(
        text: string,
        values?: PostgresParameter[],
    ): Promise<{ readonly rows: readonly Row[] }>;
}

/** PGlite database surface needed without adding it to production dependencies. */
export interface PGliteDatabaseLike extends PGliteQueryLike {
    transaction<Result>(
        operation: (transaction: PGliteQueryLike) => Promise<Result>,
    ): Promise<Result>;
    close(): Promise<void>;
}

class PGliteQueryAdapter implements PostgresQuery {
    readonly #query: PGliteQueryLike;

    constructor(query: PGliteQueryLike) {
        this.#query = query;
    }

    async query<Row extends Record<string, unknown>>(
        text: string,
        values?: readonly PostgresParameter[],
    ): Promise<{ readonly rows: readonly Row[] }> {
        return this.#query.query<Row>(text, parameters(values));
    }
}

/** Adapt PGlite's real transactions to the same minimal store query interface. */
export class PGliteDatabase implements PostgresDatabase {
    readonly #database: PGliteDatabaseLike;
    #closed = false;

    constructor(database: PGliteDatabaseLike) {
        this.#database = database;
    }

    /** Run one PGlite query. */
    async query<Row extends Record<string, unknown>>(
        text: string,
        values?: readonly PostgresParameter[],
    ): Promise<{ readonly rows: readonly Row[] }> {
        return this.#database.query<Row>(text, parameters(values));
    }

    /** Run one real PGlite transaction, optionally with repeatable-read isolation. */
    async transaction<Result>(
        operation: (transaction: PostgresQuery) => Promise<Result>,
        isolation: "read committed" | "repeatable read" = "read committed",
    ): Promise<Result> {
        return this.#database.transaction(async (transaction) => {
            const adapter = new PGliteQueryAdapter(transaction);
            if (isolation === "repeatable read") {
                await adapter.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
            }
            return operation(adapter);
        });
    }

    /** PGlite has one session, so run the operation directly on its adapter. */
    async connection<Result>(
        operation: (connection: PostgresSession) => Promise<Result>,
    ): Promise<Result> {
        return operation(this);
    }

    /** Close the owned in-process Postgres instance. */
    async close(): Promise<void> {
        if (!this.#closed) {
            this.#closed = true;
            await this.#database.close();
        }
    }
}
