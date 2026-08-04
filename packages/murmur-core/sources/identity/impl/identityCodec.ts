import type { IdentityPublicKey } from "../../crypto/index.js";
import { validateIdentityPublicKey } from "../../crypto/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/index.js";
import type { SerializedPublicIdentity } from "../types.js";

const PUBLIC_KEY_CHARACTERS = 43;

/** Serialize the one public identity key. */
export function serializePublicIdentity(identity: IdentityPublicKey): SerializedPublicIdentity {
    validateIdentityPublicKey(identity);
    return { publicKey: encodeBase64Url(identity.publicKey) };
}

/** Decode the one public identity key. */
export function deserializePublicIdentity(serialized: SerializedPublicIdentity): IdentityPublicKey {
    if (
        typeof serialized !== "object" ||
        serialized === null ||
        Array.isArray(serialized) ||
        Object.keys(serialized).length !== 1 ||
        typeof serialized.publicKey !== "string" ||
        serialized.publicKey.length !== PUBLIC_KEY_CHARACTERS
    ) {
        throw new Error("Invalid serialized public identity");
    }
    const publicKey = decodeBase64Url(serialized.publicKey);
    if (publicKey.length !== 32 || encodeBase64Url(publicKey) !== serialized.publicKey) {
        throw new Error("Invalid serialized public identity");
    }
    validateIdentityPublicKey({ publicKey });
    return { publicKey };
}

/** Return the stable identifier for a public identity. */
export function identityId(identity: IdentityPublicKey): string {
    return serializePublicIdentity(identity).publicKey;
}
