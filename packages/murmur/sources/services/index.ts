import type { MurmurSession } from "../sessions/types.js";
import { equalBytes } from "../utils/index.js";
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
        typeof registration.service.onUpdate !== "function" ||
        (registration.service.onSessionDeleted !== undefined &&
            typeof registration.service.onSessionDeleted !== "function")
    ) {
        throw new Error("Invalid Murmur service registration");
    }
}

/**
 * Create the defensive descriptor passed across the service callback boundary.
 */
export function createMurmurServiceSessionDescriptor(
    session: Pick<MurmurSession, "id" | "descriptor" | "members" | "owner" | "admins" | "policies">,
): MurmurServiceSessionDescriptor {
    if (
        !(session.id instanceof Uint8Array) ||
        session.id.length !== 32 ||
        !(session.descriptor instanceof Uint8Array) ||
        session.descriptor.length > 1024 * 1024 ||
        !(session.owner instanceof Uint8Array) ||
        session.owner.length !== 32 ||
        !Array.isArray(session.admins) ||
        !session.admins.some((admin) => equalBytes(admin, session.owner)) ||
        session.admins.some((admin) => !(admin instanceof Uint8Array) || admin.length !== 32) ||
        typeof session.policies?.adminsAssignAdmins !== "boolean" ||
        typeof session.policies.anyoneCanAddMembers !== "boolean" ||
        (session.policies.sendPolicy !== "everyone" && session.policies.sendPolicy !== "admins") ||
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
        owner: session.owner.slice(),
        admins: Object.freeze(session.admins.map((admin) => admin.slice())),
        policies: Object.freeze({ ...session.policies }),
    });
}
