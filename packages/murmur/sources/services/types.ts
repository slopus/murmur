import type { MurmurUpdate } from "../sessions/types.js";
import type { JsonValue } from "../utils/canonicalJson.js";

/** Immutable-by-convention view offered to services for one newly observed session. */
export interface MurmurServiceSessionDescriptor {
    readonly id: Uint8Array;
    readonly descriptor: Uint8Array;
    readonly members: readonly Uint8Array[];
    readonly committer: Uint8Array;
}

/**
 * Optional typed synchronization capability registered on a Murmur client.
 *
 * Returning `true` from `onNewSession` claims the session. Murmur then routes
 * its later updates exclusively to `onUpdate`.
 */
export interface MurmurService {
    onNewSession(descriptor: MurmurServiceSessionDescriptor): boolean | Promise<boolean>;
    onUpdate(update: MurmurUpdate): void | Promise<void>;
}

/** One service and the explicit stable identifier used for durable routing. */
export interface MurmurServiceRegistration {
    readonly id: string;
    readonly service: MurmurService;
}

/** JSON value accepted by service-scoped durable storage. */
export type MurmurServiceJsonValue = JsonValue;

/** Bounded lexicographic query within one service's private namespace. */
export interface MurmurServiceStorageScanOptions {
    /** Return relative keys strictly after this complete relative key. */
    readonly after?: string;
    /** Maximum entries to return, from 1 through 256. */
    readonly limit: number;
}

/**
 * JSON-only persistence scoped to one registered service.
 *
 * Keys are relative to the service namespace. Returned compound JSON values
 * are defensive, deeply frozen copies.
 */
export interface MurmurServiceStorage {
    /** Read one JSON value, or `undefined` when the key is absent. */
    get(key: string): Promise<MurmurServiceJsonValue | undefined>;
    /** Persist one canonical JSON value of at most one MiB. */
    set(key: string, value: MurmurServiceJsonValue): Promise<void>;
    /** Remove one value when present. */
    delete(key: string): Promise<void>;
    /** Read one bounded, ordered page beneath a relative prefix. */
    scan(
        prefix: string,
        options: MurmurServiceStorageScanOptions,
    ): Promise<ReadonlyMap<string, MurmurServiceJsonValue>>;
}
