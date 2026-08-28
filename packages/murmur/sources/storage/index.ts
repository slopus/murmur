import { createContextNamespace, withAfterCommit, type Context } from "@steve.kite/stdlib";

import type { MurmurStore, StoreScanOptions } from "./types.js";

export type { MurmurStore, StoreScanOptions } from "./types.js";

/** Largest bounded store scan accepted by every Murmur store. */
export const MAXIMUM_STORE_SCAN_ITEMS = 10_000;

/** Ephemeral store with serialized transactions. */
export class MemoryMurmurStore implements MurmurStore {
    readonly #values = new Map<string, Uint8Array>();
    readonly #transaction = createContextNamespace<
        { readonly store: MemoryMurmurStore; active: boolean } | undefined
    >("memory-murmur-store-transaction", undefined, { detachable: false });
    #transactionTail: Promise<void> = Promise.resolve();

    /** Return a defensive byte copy for one key. */
    async get(ctx: Context, key: string): Promise<Uint8Array | undefined> {
        return this.#access(ctx, async () => this.#get(key));
    }

    /** Store a defensive byte copy. */
    async set(ctx: Context, key: string, value: Uint8Array): Promise<void> {
        await this.#access(ctx, async () => this.#set(key, value));
    }

    /** Remove one key when present. */
    async delete(ctx: Context, key: string): Promise<void> {
        await this.#access(ctx, async () => this.#delete(key));
    }

    /** Return defensive copies of entries under one prefix. */
    async list(ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#access(ctx, async () => this.#list(prefix));
    }

    /** Return one bounded lexicographically ordered page under a prefix. */
    async scan(
        ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#access(ctx, async () => this.#scan(prefix, options));
    }

    /** Run one serialized in-memory transaction with rollback on throw. */
    async tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result> {
        const current = this.#transaction.get(ctx);
        if (current !== undefined) {
            if (current.store !== this) {
                throw new Error("Murmur transaction belongs to another store");
            }
            if (current.active) return operation(ctx);
        }

        let runAfterCommit: (() => Promise<void>) | undefined;
        const result = await this.#exclusive(async () => {
            const snapshot = new Map(
                [...this.#values].map(([key, value]) => [key, value.slice()] as const),
            );
            const [afterCommitCtx, run] = withAfterCommit(ctx);
            runAfterCommit = run;
            const state = { store: this, active: true };
            const tx = this.#transaction.set(afterCommitCtx, state);
            try {
                return await operation(tx);
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
                state.active = false;
                for (const value of snapshot.values()) {
                    value.fill(0);
                }
            }
        });
        await runAfterCommit?.();
        return result;
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
            options.limit > MAXIMUM_STORE_SCAN_ITEMS ||
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

    async #access<Result>(ctx: Context, operation: () => Promise<Result>): Promise<Result> {
        const current = this.#transaction.get(ctx);
        if (current === undefined) return this.#exclusive(operation);
        if (current.store !== this) throw new Error("Murmur transaction belongs to another store");
        return current.active ? operation() : this.#exclusive(operation);
    }
}
