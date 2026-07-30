/** Atomic value exposed by a storage transaction. */
export interface StoreTransaction {
    get(key: string): Promise<Uint8Array | undefined>;
    set(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>>;
}

/** Durable storage boundary used by browser and Node clients. */
export interface MurmurStore extends StoreTransaction {
    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result>;
}
