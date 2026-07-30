import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import type { IdentityProfile } from "../types.js";

interface SerializedProfile {
    readonly name: string;
    readonly avatar?: string;
    readonly metadata?: Readonly<Record<string, string>>;
}

/** Encode a profile to the version-one JSON representation. */
export function encodeProfilePayload(profile: IdentityProfile): Uint8Array {
    if (profile.name.length === 0 || profile.name.length > 256) {
        throw new Error("Profile name must contain 1 to 256 characters");
    }
    const serialized: SerializedProfile = {
        name: profile.name,
        ...(profile.avatar === undefined ? {} : { avatar: encodeBase64Url(profile.avatar) }),
        ...(profile.metadata === undefined ? {} : { metadata: profile.metadata }),
    };
    return utf8Encode(JSON.stringify(serialized));
}

/** Decode and validate a version-one profile. */
export function decodeProfilePayload(bytes: Uint8Array): IdentityProfile {
    const value: unknown = JSON.parse(utf8Decode(bytes));
    if (
        typeof value !== "object" ||
        value === null ||
        !("name" in value) ||
        typeof value.name !== "string" ||
        value.name.length === 0 ||
        value.name.length > 256
    ) {
        throw new Error("Invalid profile name");
    }

    let avatar: Uint8Array | undefined;
    if ("avatar" in value && value.avatar !== undefined) {
        if (typeof value.avatar !== "string") {
            throw new Error("Invalid profile avatar");
        }
        avatar = decodeBase64Url(value.avatar);
    }

    let metadata: Record<string, string> | undefined;
    if ("metadata" in value && value.metadata !== undefined) {
        if (
            typeof value.metadata !== "object" ||
            value.metadata === null ||
            Array.isArray(value.metadata) ||
            (Object.getPrototypeOf(value.metadata) !== Object.prototype &&
                Object.getPrototypeOf(value.metadata) !== null)
        ) {
            throw new Error("Invalid profile metadata");
        }
        metadata = {};
        for (const [key, entry] of Object.entries(value.metadata)) {
            if (typeof entry !== "string") {
                throw new Error("Invalid profile metadata value");
            }
            Object.defineProperty(metadata, key, {
                configurable: true,
                enumerable: true,
                value: entry,
                writable: true,
            });
        }
    }

    return {
        name: value.name,
        ...(avatar === undefined ? {} : { avatar }),
        ...(metadata === undefined ? {} : { metadata }),
    };
}
