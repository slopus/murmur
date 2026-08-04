import type { IdentityProfile } from "../identity/index.js";
import { MurmurEngine } from "./impl/engine.js";
import type { MurmurFriends, MurmurGroups, MurmurOpenOptions, MurmurSyncOptions } from "./types.js";

export type {
    MurmurFriend,
    MurmurFriends,
    MurmurFriendStatus,
    MurmurGroup,
    MurmurGroupEvent,
    MurmurGroupPage,
    MurmurGroups,
    MurmurGroupStatus,
    MurmurOpenOptions,
    MurmurSyncOptions,
} from "./types.js";

/**
 * The single browser-safe, stateful Murmur library facade.
 *
 * Construct instances with `Murmur.open()`. Friend and group operations are
 * bound to the owning instance and cannot be constructed independently.
 */
export class Murmur {
    readonly #engine: MurmurEngine;

    /** Friend bootstrap and relationship operations bound to this instance. */
    readonly friends: MurmurFriends;

    /** Opaque MLS group-stream operations bound to this instance. */
    readonly groups: MurmurGroups;

    private constructor(engine: MurmurEngine) {
        this.#engine = engine;
        this.friends = engine.friends;
        this.groups = engine.groups;
    }

    /**
     * Open or create the one identity rooted in the clean Murmur namespace.
     *
     * `initialProfile` is required for an empty namespace and ignored when a
     * root already exists. The returned instance immediately starts its
     * internal convergence worker.
     */
    static async open(options: MurmurOpenOptions): Promise<Murmur> {
        return new Murmur(await MurmurEngine.open(options));
    }

    /** Defensive copy of the one public Murmur identity key. */
    get identityKey(): Uint8Array {
        return this.#engine.identityKey;
    }

    /** Defensive copy of the local authenticated profile. */
    get profile(): IdentityProfile {
        return this.#engine.profile;
    }

    /** Persist a local profile and queue authenticated updates to active friends. */
    async setProfile(profile: IdentityProfile): Promise<void> {
        await this.#engine.setProfile(profile);
    }

    /**
     * Optionally wait for an explicit convergence boundary.
     *
     * Normal applications do not need to call this after every mutation; the
     * internal worker retries durable work automatically.
     */
    async sync(options: MurmurSyncOptions = {}): Promise<void> {
        await this.#engine.sync(options);
    }

    /** Last background convergence error, retained until observed by `sync()`. */
    get convergenceError(): Error | undefined {
        return this.#engine.convergenceError;
    }

    /** Stop convergence, await active work, and zero in-memory secrets. */
    async close(): Promise<void> {
        await this.#engine.close();
    }

    /** Alias for `close()`. */
    async destroy(): Promise<void> {
        await this.close();
    }
}
