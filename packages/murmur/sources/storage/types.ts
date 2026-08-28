import type { Context } from "@steve.kite/stdlib";

/** Bounded lexicographic scan within one key prefix. */
export interface StoreScanOptions {
    /** Return keys strictly after this complete key. */
    readonly after?: string;
    /** Maximum number of entries to materialize, at most 10,000. */
    readonly limit: number;
}

/**
 * Atomic ordered byte key/value view.
 *
 * Every Murmur feature is encoded as compound keys over this primitive.
 */
export interface MurmurStore {
    /** Return a defensive byte copy for one key, or `undefined` when absent. */
    get(ctx: Context, key: string): Promise<Uint8Array | undefined>;
    /** Store a defensive copy of one byte value. */
    set(ctx: Context, key: string, value: Uint8Array): Promise<void>;
    /** Remove one key when present. */
    delete(ctx: Context, key: string): Promise<void>;
    /**
     * Return defensive copies of every entry whose key begins with `prefix`.
     *
     * @deprecated Use bounded lexicographic `scan` paging for production work.
     */
    list(ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>>;
    /** Return one bounded lexicographically ordered page under `prefix`. */
    scan(
        ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>>;
    /**
     * Run one callback atomically with rollback on throw and supply its transaction context.
     *
     * Nested calls for the same store reuse the transaction carried by `ctx`.
     */
    tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result>;
}
