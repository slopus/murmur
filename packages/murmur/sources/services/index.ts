import type { MurmurSession } from "../sessions/types.js";
import { validateServiceId } from "./impl/serviceId.js";
import type { MurmurServiceRegistration, MurmurServiceSessionDescriptor } from "./types.js";

export { validateServiceId } from "./impl/serviceId.js";
export type {
    MurmurService,
    MurmurServiceRegistration,
    MurmurServiceSessionDescriptor,
} from "./types.js";

/** Validate one service registration before it participates in durable routing. */
export function validateMurmurServiceRegistration(registration: MurmurServiceRegistration): void {
    if (
        registration === null ||
        typeof registration !== "object" ||
        typeof registration.id !== "string"
    ) {
        throw new Error("Invalid Murmur service registration");
    }
    try {
        validateServiceId(registration.id);
    } catch {
        throw new Error("Invalid Murmur service registration");
    }
    if (
        registration.service === null ||
        typeof registration.service !== "object" ||
        typeof registration.service.onNewSession !== "function" ||
        typeof registration.service.onUpdate !== "function"
    ) {
        throw new Error("Invalid Murmur service registration");
    }
}

/**
 * Create the defensive descriptor passed across the service callback boundary.
 */
export function createMurmurServiceSessionDescriptor(
    session: Pick<MurmurSession, "id" | "descriptor" | "members" | "committer">,
): MurmurServiceSessionDescriptor {
    if (
        !(session.id instanceof Uint8Array) ||
        session.id.length !== 32 ||
        !(session.descriptor instanceof Uint8Array) ||
        session.descriptor.length > 1024 * 1024 ||
        !(session.committer instanceof Uint8Array) ||
        session.committer.length !== 32 ||
        !Array.isArray(session.members) ||
        session.members.length < 1 ||
        session.members.length > 256 ||
        session.members.some((member) => !(member instanceof Uint8Array) || member.length !== 32)
    ) {
        throw new Error("Invalid Murmur service session descriptor");
    }
    return Object.freeze({
        id: session.id.slice(),
        descriptor: session.descriptor.slice(),
        members: Object.freeze(session.members.map((member) => member.slice())),
        committer: session.committer.slice(),
    });
}
