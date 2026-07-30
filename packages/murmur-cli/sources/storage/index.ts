import { chmodSync, closeSync, existsSync, lstatSync, openSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import type { MurmurStore, StoreTransaction } from "@slopus/murmur";

const MAXIMUM_KEY_CHARACTERS = 4_096;
const MAXIMUM_VALUE_BYTES = 64 * 1024 * 1024;

function validateKey(key: string, allowEmpty: boolean = false): void {
    if (
        typeof key !== "string" ||
        (!allowEmpty && key.length === 0) ||
        key.length > MAXIMUM_KEY_CHARACTERS
    ) {
        throw new Error("Invalid Murmur SQLite key");
    }
}

function validateValue(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length > MAXIMUM_VALUE_BYTES) {
        throw new Error("Invalid Murmur SQLite value");
    }
}

function storedBytes(value: unknown): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error("Invalid Murmur SQLite bytes");
    }
    return value.slice();
}

/** Durable SQLite implementation of the core MurmurStore contract. */
export class SqliteMurmurStore implements MurmurStore {
    readonly #database: DatabaseSync;
    readonly #path: string | undefined;
    #tail: Promise<void> = Promise.resolve();
    #closed = false;

    constructor(path: string) {
        if (path.length === 0) {
            throw new Error("Murmur SQLite path cannot be empty");
        }
        this.#path = path === ":memory:" ? undefined : path;
        this.#secureDatabaseFiles(true);
        this.#database = new DatabaseSync(path);
        this.#database.exec("PRAGMA foreign_keys = ON");
        if (path !== ":memory:") {
            this.#database.exec("PRAGMA journal_mode = WAL");
        }
        this.#database.exec(`
            CREATE TABLE IF NOT EXISTS key_values (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            )
        `);
        this.#secureDatabaseFiles();
    }

    async get(key: string): Promise<Uint8Array | undefined> {
        return this.#exclusive(async () => this.#get(key));
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        await this.#exclusive(async () => this.#set(key, value));
    }

    async delete(key: string): Promise<void> {
        await this.#exclusive(async () => this.#delete(key));
    }

    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#exclusive(async () => this.#list(prefix));
    }

    async transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#exclusive(async () => {
            this.#database.exec("BEGIN IMMEDIATE");
            const transaction: StoreTransaction = {
                get: async (key): Promise<Uint8Array | undefined> => this.#get(key),
                set: async (key, value): Promise<void> => this.#set(key, value),
                delete: async (key): Promise<void> => this.#delete(key),
                list: async (prefix): Promise<ReadonlyMap<string, Uint8Array>> =>
                    this.#list(prefix),
            };
            try {
                const result = await operation(transaction);
                this.#database.exec("COMMIT");
                this.#secureDatabaseFiles();
                return result;
            } catch (error: unknown) {
                this.#database.exec("ROLLBACK");
                throw error;
            }
        });
    }

    /** Close the database after all preceding work has completed. */
    async close(): Promise<void> {
        await this.#exclusive(async () => {
            if (this.#closed) {
                return;
            }
            this.#closed = true;
            this.#database.close();
            this.#secureDatabaseFiles();
        });
    }

    #get(key: string): Uint8Array | undefined {
        this.#ensureOpen();
        validateKey(key);
        const row = this.#database.prepare("SELECT value FROM key_values WHERE key = ?").get(key);
        return row === undefined ? undefined : storedBytes(row.value);
    }

    #set(key: string, value: Uint8Array): void {
        this.#ensureOpen();
        validateKey(key);
        validateValue(value);
        this.#database
            .prepare(
                `INSERT INTO key_values(key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
            )
            .run(key, value.slice());
        this.#secureDatabaseFiles();
    }

    #delete(key: string): void {
        this.#ensureOpen();
        validateKey(key);
        this.#database.prepare("DELETE FROM key_values WHERE key = ?").run(key);
    }

    #list(prefix: string): ReadonlyMap<string, Uint8Array> {
        this.#ensureOpen();
        validateKey(prefix, true);
        const rows = this.#database
            .prepare(
                `SELECT key, value FROM key_values
                 WHERE substr(key, 1, ?) = ?
                 ORDER BY key`,
            )
            .all(prefix.length, prefix);
        const result = new Map<string, Uint8Array>();
        for (const row of rows) {
            if (typeof row.key !== "string") {
                throw new Error("Invalid Murmur SQLite row key");
            }
            result.set(row.key, storedBytes(row.value));
        }
        return result;
    }

    #ensureOpen(): void {
        if (this.#closed) {
            throw new Error("Murmur SQLite store is closed");
        }
    }

    #secureDatabaseFiles(create: boolean = false): void {
        if (this.#path === undefined) {
            return;
        }
        if (create && !existsSync(this.#path)) {
            closeSync(openSync(this.#path, "wx", 0o600));
        }
        for (const path of [this.#path, `${this.#path}-wal`, `${this.#path}-shm`]) {
            if (!existsSync(path)) {
                continue;
            }
            const statistics = lstatSync(path);
            if (!statistics.isFile() || statistics.isSymbolicLink()) {
                throw new Error("Murmur SQLite state must use regular private files");
            }
            chmodSync(path, 0o600);
            if ((lstatSync(path).mode & 0o077) !== 0) {
                throw new Error("Murmur SQLite state permissions are not private");
            }
        }
    }

    async #exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        let release: (() => void) | undefined;
        const prior = this.#tail;
        this.#tail = new Promise<void>((resolve) => {
            release = resolve;
        });
        await prior;
        try {
            return await operation();
        } finally {
            release?.();
        }
    }
}
