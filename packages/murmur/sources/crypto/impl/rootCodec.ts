import {
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import type { IdentityKeyPair, StoredIdentityRoot } from "../types.js";
import { importIdentityKeyPair, validateIdentityKeyPair } from "./identityKeys.js";

/** Serialize the one root secret for application-owned secure storage. */
export function encodeIdentityRoot(identity: IdentityKeyPair): Uint8Array {
    validateIdentityKeyPair(identity);
    const stored: StoredIdentityRoot = {
        version: 1,
        secretKey: encodeBase64Url(identity.secretKey),
    };
    return utf8Encode(JSON.stringify(stored));
}

/** Decode the strict one-root storage representation. */
export function decodeIdentityRoot(bytes: Uint8Array): IdentityKeyPair {
    if (bytes.length > 256) {
        throw new Error("Invalid stored identity root");
    }
    const decoded: unknown = JSON.parse(utf8Decode(bytes));
    if (
        typeof decoded !== "object" ||
        decoded === null ||
        Array.isArray(decoded) ||
        Object.keys(decoded).length !== 2 ||
        !("version" in decoded) ||
        decoded.version !== 1 ||
        !("secretKey" in decoded) ||
        typeof decoded.secretKey !== "string" ||
        decoded.secretKey.length !== 43
    ) {
        throw new Error("Invalid stored identity root");
    }
    const secretKey = decodeBase64Url(decoded.secretKey);
    try {
        return importIdentityKeyPair(secretKey);
    } finally {
        zeroBytes(secretKey);
    }
}
