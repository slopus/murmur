import type { MurmurStore, StoreScanOptions, StoreTransaction } from "./types.js";

export type { MurmurStore, StoreScanOptions, StoreTransaction } from "./types.js";

/** Ephemeral store with serialized transactions. */
export class MemoryMurmurStore implements MurmurStore {
    readonly #values = new Map<string, Uint8Array>();
    #transactionTail: Promise<void> = Promise.resolve();

    /** Return a defensive byte copy for one key. */
    async get(key: string): Promise<Uint8Array | undefined> {
        return this.#exclusive(async () => this.#get(key));
    }

    /** Store a defensive byte copy. */
    async set(key: string, value: Uint8Array): Promise<void> {
        await this.#exclusive(async () => this.#set(key, value));
    }

    /** Remove one key when present. */
    async delete(key: string): Promise<void> {
        await this.#exclusive(async () => this.#delete(key));
    }

    /** Return defensive copies of entries under one prefix. */
    async list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#exclusive(async () => this.#list(prefix));
    }

    /** Return one bounded lexicographically ordered page under a prefix. */
    async scan(
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#exclusive(async () => this.#scan(prefix, options));
    }

    /** Run one serialized in-memory transaction with rollback on throw. */
    async transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return this.#exclusive(async () => {
            const snapshot = new Map(
                [...this.#values].map(([key, value]) => [key, value.slice()] as const),
            );
            const transaction: StoreTransaction = {
                get: async (key): Promise<Uint8Array | undefined> => this.#get(key),
                set: async (key, value): Promise<void> => this.#set(key, value),
                delete: async (key): Promise<void> => this.#delete(key),
                list: async (prefix): Promise<ReadonlyMap<string, Uint8Array>> =>
                    this.#list(prefix),
                scan: async (prefix, options): Promise<ReadonlyMap<string, Uint8Array>> =>
                    this.#scan(prefix, options),
            };
            try {
                return await operation(transaction);
            } catch (error: unknown) {
                for (const value of this.#values.values()) {
                    value.fill(0);
                }
                this.#values.clear();
                for (const [key, value] of snapshot) {
                    this.#values.set(key, value);
                }
                snapshot.clear();
                throw error;
            } finally {
                for (const value of snapshot.values()) {
                    value.fill(0);
                }
            }
        });
    }

    #get(key: string): Uint8Array | undefined {
        return this.#values.get(key)?.slice();
    }

    #set(key: string, value: Uint8Array): void {
        this.#values.get(key)?.fill(0);
        this.#values.set(key, value.slice());
    }

    #delete(key: string): void {
        this.#values.get(key)?.fill(0);
        this.#values.delete(key);
    }

    #list(prefix: string): ReadonlyMap<string, Uint8Array> {
        const result = new Map<string, Uint8Array>();
        for (const [key, value] of this.#values) {
            if (key.startsWith(prefix)) {
                result.set(key, value.slice());
            }
        }
        return result;
    }

    #scan(prefix: string, options: StoreScanOptions): ReadonlyMap<string, Uint8Array> {
        if (
            !Number.isSafeInteger(options.limit) ||
            options.limit < 1 ||
            options.limit > 10_000 ||
            (options.after !== undefined && !options.after.startsWith(prefix))
        ) {
            throw new Error("Invalid Murmur store scan");
        }
        const result = new Map<string, Uint8Array>();
        const keys = [...this.#values.keys()]
            .filter(
                (key) =>
                    key.startsWith(prefix) && (options.after === undefined || key > options.after),
            )
            .sort();
        for (const key of keys.slice(0, options.limit)) {
            result.set(key, this.#values.get(key)!.slice());
        }
        return result;
    }

    async #exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        let release: (() => void) | undefined;
        const prior = this.#transactionTail;
        this.#transactionTail = new Promise<void>((resolve) => {
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
