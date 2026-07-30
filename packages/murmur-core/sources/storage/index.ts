import type { MurmurStore, StoreTransaction } from "./types.js";

export type { MurmurStore, StoreTransaction } from "./types.js";

/** Ephemeral store with serialized transactions. */
export class MemoryMurmurStore implements MurmurStore {
    readonly #values = new Map<string, Uint8Array>();
    #transactionTail: Promise<void> = Promise.resolve();

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
            const snapshot = new Map(
                [...this.#values].map(([key, value]) => [key, value.slice()] as const),
            );
            const transaction: StoreTransaction = {
                get: async (key): Promise<Uint8Array | undefined> => this.#get(key),
                set: async (key, value): Promise<void> => this.#set(key, value),
                delete: async (key): Promise<void> => this.#delete(key),
                list: async (prefix): Promise<ReadonlyMap<string, Uint8Array>> =>
                    this.#list(prefix),
            };
            try {
                return await operation(transaction);
            } catch (error: unknown) {
                this.#values.clear();
                for (const [key, value] of snapshot) {
                    this.#values.set(key, value);
                }
                throw error;
            }
        });
    }

    #get(key: string): Uint8Array | undefined {
        return this.#values.get(key)?.slice();
    }

    #set(key: string, value: Uint8Array): void {
        this.#values.set(key, value.slice());
    }

    #delete(key: string): void {
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
