import type { MurmurUpdate } from "../sessions/types.js";
import type { MurmurSessionPolicies } from "../sessions/types.js";

/** Immutable-by-convention view offered to services for one newly observed session. */
export interface MurmurServiceSessionDescriptor {
    readonly id: Uint8Array;
    readonly descriptor: Uint8Array;
    readonly members: readonly Uint8Array[];
    readonly owner: Uint8Array;
    readonly admins: readonly Uint8Array[];
    readonly policies: MurmurSessionPolicies;
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
