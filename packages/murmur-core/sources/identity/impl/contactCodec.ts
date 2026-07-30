import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";
import { decodeProfilePayload, encodeProfilePayload } from "./profileCodec.js";
import type { Contact } from "../types.js";

/** Encode one authenticated contact for local persistence. */
export function encodeContact(contact: Contact): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            identity: {
                signingKey: encodeBase64Url(contact.identity.signingKey),
                encryptionKey: encodeBase64Url(contact.identity.encryptionKey),
            },
            profile: encodeBase64Url(encodeProfilePayload(contact.profile)),
            addedAt: contact.addedAt,
            updatedAt: contact.updatedAt,
        }),
    );
}

/** Decode and validate one locally persisted contact. */
export function decodeContact(bytes: Uint8Array): Contact {
    const value: unknown = JSON.parse(utf8Decode(bytes));
    if (
        typeof value !== "object" ||
        value === null ||
        !("identity" in value) ||
        typeof value.identity !== "object" ||
        value.identity === null ||
        !("signingKey" in value.identity) ||
        typeof value.identity.signingKey !== "string" ||
        !("encryptionKey" in value.identity) ||
        typeof value.identity.encryptionKey !== "string" ||
        !("profile" in value) ||
        typeof value.profile !== "string" ||
        !("addedAt" in value) ||
        typeof value.addedAt !== "number" ||
        !Number.isSafeInteger(value.addedAt) ||
        value.addedAt < 0 ||
        !("updatedAt" in value) ||
        typeof value.updatedAt !== "number" ||
        !Number.isSafeInteger(value.updatedAt) ||
        value.updatedAt < value.addedAt
    ) {
        throw new Error("Invalid persisted contact");
    }
    const signingKey = decodeBase64Url(value.identity.signingKey);
    const encryptionKey = decodeBase64Url(value.identity.encryptionKey);
    if (signingKey.length !== 32 || encryptionKey.length !== 32) {
        throw new Error("Invalid persisted contact identity");
    }
    return {
        identity: { signingKey, encryptionKey },
        profile: decodeProfilePayload(decodeBase64Url(value.profile)),
        addedAt: value.addedAt,
        updatedAt: value.updatedAt,
    };
}
