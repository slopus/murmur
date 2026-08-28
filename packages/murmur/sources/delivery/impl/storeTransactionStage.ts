import type { Context } from "@steve.kite/stdlib";

import {
    MAXIMUM_STORE_SCAN_ITEMS,
    type MurmurStore,
    type StoreScanOptions,
} from "../../storage/index.js";
import { zeroBytes } from "../../utils/index.js";

const RESERVED_PREFIX = "murmur/";

/**
 * Isolated internal handler-write overlay inside one outer transaction.
 *
 * Terminal classification discards the overlay while successful processing
 * flushes it into the outer transaction before queue progress is persisted.
 */
export class StagedMurmurStore implements MurmurStore {
    readonly #base: MurmurStore;
    readonly #baseCtx: Context;
    readonly #changes = new Map<string, Uint8Array | null>();
    #closed = false;

    readonly #allowMurmurMutations: boolean;

    constructor(base: MurmurStore, baseCtx: Context, allowMurmurMutations: boolean = false) {
        this.#base = base;
        this.#baseCtx = baseCtx;
        this.#allowMurmurMutations = allowMurmurMutations;
    }

    async get(_ctx: Context, key: string): Promise<Uint8Array | undefined> {
        this.#assertOpen();
        const staged = this.#changes.get(key);
        if (staged !== undefined) return staged === null ? undefined : staged.slice();
        return this.#base.get(this.#baseCtx, key);
    }

    async set(_ctx: Context, key: string, value: Uint8Array): Promise<void> {
        this.#assertMutableKey(key);
        const prior = this.#changes.get(key);
        if (prior instanceof Uint8Array) zeroBytes(prior);
        this.#changes.set(key, value.slice());
    }

    async delete(_ctx: Context, key: string): Promise<void> {
        this.#assertMutableKey(key);
        const prior = this.#changes.get(key);
        if (prior instanceof Uint8Array) zeroBytes(prior);
        this.#changes.set(key, null);
    }

    async list(_ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        this.#assertOpen();
        const values = new Map(await this.#base.list(this.#baseCtx, prefix));
        for (const [key, value] of this.#changes) {
            if (!key.startsWith(prefix)) continue;
            if (value === null) {
                values.delete(key);
            } else {
                values.set(key, value.slice());
            }
        }
        return values;
    }

    async scan(
        _ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        if (
            !Number.isSafeInteger(options.limit) ||
            options.limit < 1 ||
            options.limit > MAXIMUM_STORE_SCAN_ITEMS ||
            (options.after !== undefined && !options.after.startsWith(prefix))
        ) {
            throw new Error("Invalid staged store scan");
        }
        const values = new Map<string, Uint8Array>();
        let after = options.after;
        while (values.size < options.limit) {
            const page = await this.#base.scan(this.#baseCtx, prefix, {
                ...(after === undefined ? {} : { after }),
                limit: options.limit,
            });
            for (const [key, value] of page) {
                if (!this.#changes.has(key)) values.set(key, value);
            }
            const last = [...page.keys()].at(-1);
            if (page.size < options.limit || last === undefined) break;
            after = last;
        }
        for (const [key, value] of this.#changes) {
            if (
                key.startsWith(prefix) &&
                (options.after === undefined || key > options.after) &&
                value !== null
            ) {
                values.set(key, value.slice());
            }
        }
        const result = new Map<string, Uint8Array>();
        const keys = [...values.keys()]
            .filter((key) => options.after === undefined || key > options.after)
            .sort()
            .slice(0, options.limit);
        for (const key of keys) result.set(key, values.get(key)!.slice());
        return result;
    }

    async commit(_ctx: Context): Promise<void> {
        this.#assertOpen();
        this.#closed = true;
        try {
            for (const [key, value] of this.#changes) {
                if (value === null) {
                    await this.#base.delete(this.#baseCtx, key);
                } else {
                    await this.#base.set(this.#baseCtx, key, value);
                }
            }
        } finally {
            this.#destroyChanges();
        }
    }

    discard(): void {
        if (this.#closed) return;
        this.#closed = true;
        this.#destroyChanges();
    }

    async tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result> {
        this.#assertOpen();
        return operation(ctx);
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Staged store transaction is closed");
    }

    #assertMutableKey(key: string): void {
        this.#assertOpen();
        if (!this.#allowMurmurMutations && key.startsWith(RESERVED_PREFIX)) {
            throw new Error("Application handler cannot mutate delivery processor state");
        }
    }

    #destroyChanges(): void {
        for (const value of this.#changes.values()) {
            if (value instanceof Uint8Array) zeroBytes(value);
        }
        this.#changes.clear();
    }
}
