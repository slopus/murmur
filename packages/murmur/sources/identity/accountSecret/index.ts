import { gcm } from "@noble/ciphers/aes";
import {
    importIdentityKeyPair,
    randomBytes,
    validateIdentityKeyPair,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import { zeroBytes } from "../../utils/index.js";
import {
    accountSecretBlobAssociatedData,
    decodeAccountSecretBlob,
    decodeAccountSecretPayload,
    encodeAccountSecretBlob,
    encodeAccountSecretPayload,
} from "./impl/accountSecretCodec.js";
import {
    ACCOUNT_SECRET_GENERATED_BYTES,
    ACCOUNT_SECRET_SALT_BYTES,
    decodeGeneratedAccountSecret,
    deriveAccountWrappingKey,
    encodeGeneratedAccountSecret,
    validateAccountSecretPassword,
} from "./impl/accountSecretKdf.js";
import type { CreatedAccountSecret } from "./types.js";

export type { CreatedAccountSecret } from "./types.js";

const NONCE_BYTES = 12;
const AEAD_TAG_BYTES = 16;

async function encryptPayload(
    payload: Uint8Array,
    generatedSecret: Uint8Array,
    password: string,
): Promise<string> {
    const salt = randomBytes(ACCOUNT_SECRET_SALT_BYTES);
    const nonce = randomBytes(NONCE_BYTES);
    let wrappingKey: Uint8Array | undefined;
    let associatedData: Uint8Array | undefined;
    let ciphertext: Uint8Array | undefined;
    try {
        wrappingKey = await deriveAccountWrappingKey(generatedSecret, password, salt);
        associatedData = accountSecretBlobAssociatedData(
            salt,
            nonce,
            payload.length + AEAD_TAG_BYTES,
        );
        ciphertext = gcm(wrappingKey, nonce, associatedData).encrypt(payload);
        return encodeAccountSecretBlob(salt, nonce, ciphertext);
    } finally {
        zeroBytes(salt);
        zeroBytes(nonce);
        if (wrappingKey !== undefined) zeroBytes(wrappingKey);
        if (associatedData !== undefined) zeroBytes(associatedData);
        if (ciphertext !== undefined) zeroBytes(ciphertext);
    }
}

async function decryptPayload(
    blob: string,
    generatedSecret: Uint8Array,
    password: string,
): Promise<Uint8Array> {
    const decoded = decodeAccountSecretBlob(blob);
    let wrappingKey: Uint8Array | undefined;
    try {
        wrappingKey = await deriveAccountWrappingKey(generatedSecret, password, decoded.salt);
        try {
            return gcm(wrappingKey, decoded.nonce, decoded.associatedData).decrypt(
                decoded.ciphertext,
            );
        } catch {
            throw new Error("Unable to unlock account secret");
        }
    } finally {
        zeroBytes(decoded.associatedData);
        zeroBytes(decoded.ciphertext);
        zeroBytes(decoded.nonce);
        zeroBytes(decoded.salt);
        if (wrappingKey !== undefined) zeroBytes(wrappingKey);
    }
}

/**
 * Generate and wrap a Murmur identity root for application-owned persistence.
 *
 * The returned generated string and the supplied password are both required to
 * unlock `blob`. Murmur does not retain either value and provides no reset or
 * recovery path. The application should store the blob and generated string in
 * locations appropriate for its recovery model.
 *
 * @param identity - Valid Murmur identity whose 32-byte root will be wrapped.
 * @param password - Non-empty user password of at most 1,024 UTF-8 bytes.
 * @returns A new high-entropy generated string and opaque encrypted blob.
 * @throws Error when the identity or password is invalid.
 */
export async function createAccountSecret(
    identity: IdentityKeyPair,
    password: string,
): Promise<CreatedAccountSecret> {
    validateIdentityKeyPair(identity);
    validateAccountSecretPassword(password);
    const generatedSecretBytes = randomBytes(ACCOUNT_SECRET_GENERATED_BYTES);
    const payload = encodeAccountSecretPayload(identity.secretKey);
    try {
        const generatedSecret = encodeGeneratedAccountSecret(generatedSecretBytes);
        const blob = await encryptPayload(payload, generatedSecretBytes, password);
        return Object.freeze({ blob, generatedSecret });
    } finally {
        zeroBytes(generatedSecretBytes);
        zeroBytes(payload);
    }
}

/**
 * Unlock an application-owned account-secret blob into the original identity.
 *
 * Neither input is retained. Authentication failure, malformed data, and
 * unsupported versions throw; this function never returns a partial identity.
 * The caller owns the returned key pair and should destroy it when finished.
 *
 * @param blob - Opaque blob previously returned by `createAccountSecret`.
 * @param generatedSecret - High-entropy generated string returned at creation.
 * @param password - User password protecting this blob.
 * @returns The reconstructed identity key pair derived from the wrapped root.
 * @throws Error when any input is invalid or authentication fails.
 */
export async function unlockAccountSecret(
    blob: string,
    generatedSecret: string,
    password: string,
): Promise<IdentityKeyPair> {
    validateAccountSecretPassword(password);
    const generatedSecretBytes = decodeGeneratedAccountSecret(generatedSecret);
    let payload: Uint8Array | undefined;
    let identityRoot: Uint8Array | undefined;
    try {
        payload = await decryptPayload(blob, generatedSecretBytes, password);
        identityRoot = decodeAccountSecretPayload(payload);
        return importIdentityKeyPair(identityRoot);
    } finally {
        zeroBytes(generatedSecretBytes);
        if (payload !== undefined) zeroBytes(payload);
        if (identityRoot !== undefined) zeroBytes(identityRoot);
    }
}

/**
 * Re-encrypt an account-secret blob under a changed password.
 *
 * Rewrapping authenticates and preserves the complete encrypted root-material
 * payload, generates a fresh salt and nonce, and keeps the same generated
 * secret. The old password remains necessary for this local operation; there
 * is no server-assisted reset path.
 *
 * @param blob - Existing opaque account-secret blob.
 * @param generatedSecret - Existing high-entropy generated string.
 * @param currentPassword - Password currently protecting the blob.
 * @param newPassword - Non-empty replacement password of at most 1,024 UTF-8 bytes.
 * @returns A fresh opaque blob protected by `generatedSecret` and `newPassword`.
 * @throws Error when any input is invalid or the existing blob cannot be unlocked.
 */
export async function rewrapAccountSecret(
    blob: string,
    generatedSecret: string,
    currentPassword: string,
    newPassword: string,
): Promise<string> {
    validateAccountSecretPassword(currentPassword);
    validateAccountSecretPassword(newPassword);
    const generatedSecretBytes = decodeGeneratedAccountSecret(generatedSecret);
    let payload: Uint8Array | undefined;
    let identityRoot: Uint8Array | undefined;
    try {
        payload = await decryptPayload(blob, generatedSecretBytes, currentPassword);
        identityRoot = decodeAccountSecretPayload(payload);
        return await encryptPayload(payload, generatedSecretBytes, newPassword);
    } finally {
        zeroBytes(generatedSecretBytes);
        if (payload !== undefined) zeroBytes(payload);
        if (identityRoot !== undefined) zeroBytes(identityRoot);
    }
}
