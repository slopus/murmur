/** Atomic value exposed by a storage transaction. */
export interface StoreTransaction {
    /** Return a defensive byte copy for one key, or `undefined` when absent. */
    get(key: string): Promise<Uint8Array | undefined>;
    /** Store a defensive copy of one byte value. */
    set(key: string, value: Uint8Array): Promise<void>;
    /** Remove one key when present. */
    delete(key: string): Promise<void>;
    /** Return defensive copies of every entry whose key begins with `prefix`. */
    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>>;
}

/** Durable storage boundary used by browser and Node clients. */
export interface MurmurStore extends StoreTransaction {
    /**
     * Run one callback atomically with rollback on throw.
     *
     * The transaction object must not open a nested transaction.
     */
    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result>;
}
