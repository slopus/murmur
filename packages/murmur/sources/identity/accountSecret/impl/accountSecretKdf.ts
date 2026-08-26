import { hkdf } from "@noble/hashes/hkdf";
import { scryptAsync } from "@noble/hashes/scrypt";
import { sha256 } from "@noble/hashes/sha2";
import {
    concatBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Encode,
    zeroBytes,
} from "../../../utils/index.js";

export const ACCOUNT_SECRET_GENERATED_BYTES = 32;
export const ACCOUNT_SECRET_SALT_BYTES = 32;
export const SCRYPT_LOG_N = 15;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;

const WRAPPING_KEY_BYTES = 32;
const MAXIMUM_PASSWORD_BYTES = 1_024;
const GENERATED_SECRET_PREFIX = "murmur-as1-";
const GENERATED_COMPONENT_INFO = utf8Encode("murmur/account-secret/generated-component/v1");
const WRAPPING_KEY_INFO = utf8Encode("murmur/account-secret/wrapping-key/v1");

function encodePassword(password: string): Uint8Array {
    if (typeof password !== "string" || password.length === 0) {
        throw new Error("Account secret password must not be empty");
    }
    const bytes = utf8Encode(password);
    if (bytes.length > MAXIMUM_PASSWORD_BYTES) {
        zeroBytes(bytes);
        throw new Error(`Account secret password must not exceed ${MAXIMUM_PASSWORD_BYTES} bytes`);
    }
    return bytes;
}

/** Validate a password before performing any account-secret cryptography. */
export function validateAccountSecretPassword(password: string): void {
    const bytes = encodePassword(password);
    zeroBytes(bytes);
}

/** Serialize the generated random component as one recognizable strong string. */
export function encodeGeneratedAccountSecret(secret: Uint8Array): string {
    if (secret.length !== ACCOUNT_SECRET_GENERATED_BYTES) {
        throw new Error("Generated account secret must be 32 bytes");
    }
    return `${GENERATED_SECRET_PREFIX}${encodeBase64Url(secret)}`;
}

/** Decode and validate the recognizable generated-secret representation. */
export function decodeGeneratedAccountSecret(value: string): Uint8Array {
    if (
        typeof value !== "string" ||
        value.length !== GENERATED_SECRET_PREFIX.length + 43 ||
        !value.startsWith(GENERATED_SECRET_PREFIX)
    ) {
        throw new Error("Invalid generated account secret");
    }
    const encoded = value.slice(GENERATED_SECRET_PREFIX.length);
    if (
        !/^[A-Za-z0-9_-]{43}$/.test(encoded) ||
        !"AEIMQUYcgkosw048".includes(encoded.at(-1) ?? "")
    ) {
        throw new Error("Invalid generated account secret");
    }
    let bytes: Uint8Array;
    try {
        bytes = decodeBase64Url(encoded);
    } catch {
        throw new Error("Invalid generated account secret");
    }
    if (bytes.length !== ACCOUNT_SECRET_GENERATED_BYTES) {
        zeroBytes(bytes);
        throw new Error("Invalid generated account secret");
    }
    return bytes;
}

/** Derive one wrapping key from independent generated-secret and password components. */
export async function deriveAccountWrappingKey(
    generatedSecret: Uint8Array,
    password: string,
    salt: Uint8Array,
): Promise<Uint8Array> {
    if (generatedSecret.length !== ACCOUNT_SECRET_GENERATED_BYTES) {
        throw new Error("Generated account secret must be 32 bytes");
    }
    if (salt.length !== ACCOUNT_SECRET_SALT_BYTES) {
        throw new Error("Account secret salt must be 32 bytes");
    }

    const passwordBytes = encodePassword(password);
    let generatedComponent: Uint8Array | undefined;
    let passwordComponent: Uint8Array | undefined;
    let combinedComponents: Uint8Array | undefined;
    try {
        generatedComponent = hkdf(
            sha256,
            generatedSecret,
            salt,
            GENERATED_COMPONENT_INFO,
            WRAPPING_KEY_BYTES,
        );
        passwordComponent = await scryptAsync(passwordBytes, salt, {
            N: 2 ** SCRYPT_LOG_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            dkLen: WRAPPING_KEY_BYTES,
            maxmem: 64 * 1_024 * 1_024,
        });
        combinedComponents = concatBytes(generatedComponent, passwordComponent);
        return hkdf(sha256, combinedComponents, salt, WRAPPING_KEY_INFO, WRAPPING_KEY_BYTES);
    } finally {
        zeroBytes(passwordBytes);
        if (generatedComponent !== undefined) zeroBytes(generatedComponent);
        if (passwordComponent !== undefined) zeroBytes(passwordComponent);
        if (combinedComponents !== undefined) zeroBytes(combinedComponents);
    }
}
