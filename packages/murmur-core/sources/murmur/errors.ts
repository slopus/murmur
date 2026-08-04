/**
 * An active friend has reserved every bounded local one-use KeyPackage
 * without completing or retiring those reservations.
 *
 * The bounded pool deliberately fails closed instead of allocating
 * attacker-controlled unbounded private state or reusing a consumed package.
 */
export class MurmurKeyPackagePoolExhaustedError extends Error {
    readonly #peerIdentityKey: Uint8Array;

    constructor(peerIdentityKey: Uint8Array) {
        super("Murmur KeyPackage pool is exhausted by unretired reservations");
        this.name = "MurmurKeyPackagePoolExhaustedError";
        this.#peerIdentityKey = peerIdentityKey.slice();
    }

    /** Defensive copy of the friend whose reservation pool is exhausted. */
    get peerIdentityKey(): Uint8Array {
        return this.#peerIdentityKey.slice();
    }
}

/** Copy a retained convergence error without erasing its public domain type. */
export function copyMurmurError(error: Error): Error {
    if (error instanceof MurmurKeyPackagePoolExhaustedError) {
        const peer = error.peerIdentityKey;
        try {
            return new MurmurKeyPackagePoolExhaustedError(peer);
        } finally {
            peer.fill(0);
        }
    }
    const copy = new Error(error.message);
    copy.name = error.name;
    return copy;
}
