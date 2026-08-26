import { decodeBase64Url, encodeBase64Url, equalBytes, zeroBytes } from "../../../utils/index.js";
import { ACCOUNT_SECRET_SALT_BYTES, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R } from "./accountSecretKdf.js";

const BLOB_MAGIC = new Uint8Array([0x4d, 0x52, 0x41, 0x53]);
const BLOB_VERSION = 1;
const KDF_SCRYPT = 1;
const AEAD_AES_256_GCM = 1;
const NONCE_BYTES = 12;
const AEAD_TAG_BYTES = 16;
const BLOB_HEADER_BYTES = 58;
const MAXIMUM_BLOB_BYTES = 65_536;
const PAYLOAD_VERSION = 1;
const IDENTITY_ROOT_FIELD = 1;
const IDENTITY_ROOT_BYTES = 32;
const PAYLOAD_FIELD_HEADER_BYTES = 3;
const MINIMUM_PAYLOAD_BYTES = 2 + PAYLOAD_FIELD_HEADER_BYTES + IDENTITY_ROOT_BYTES;

export interface DecodedAccountSecretBlob {
    readonly associatedData: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly nonce: Uint8Array;
    readonly salt: Uint8Array;
}

function invalidBlob(): Error {
    return new Error("Invalid account secret blob");
}

function blobHeader(salt: Uint8Array, nonce: Uint8Array, ciphertextLength: number): Uint8Array {
    if (salt.length !== ACCOUNT_SECRET_SALT_BYTES || nonce.length !== NONCE_BYTES) {
        throw invalidBlob();
    }
    if (
        !Number.isSafeInteger(ciphertextLength) ||
        ciphertextLength < MINIMUM_PAYLOAD_BYTES + AEAD_TAG_BYTES ||
        ciphertextLength > MAXIMUM_BLOB_BYTES - BLOB_HEADER_BYTES
    ) {
        throw invalidBlob();
    }

    const header = new Uint8Array(BLOB_HEADER_BYTES);
    header.set(BLOB_MAGIC, 0);
    header[4] = BLOB_VERSION;
    header[5] = KDF_SCRYPT;
    header[6] = AEAD_AES_256_GCM;
    header[7] = SCRYPT_LOG_N;
    header[8] = SCRYPT_R;
    header[9] = SCRYPT_P;
    header.set(salt, 10);
    header.set(nonce, 42);
    new DataView(header.buffer, header.byteOffset, header.byteLength).setUint32(
        54,
        ciphertextLength,
        false,
    );
    return header;
}

/** Build the exact authenticated account-secret blob header. */
export function accountSecretBlobAssociatedData(
    salt: Uint8Array,
    nonce: Uint8Array,
    ciphertextLength: number,
): Uint8Array {
    return blobHeader(salt, nonce, ciphertextLength);
}

/** Serialize one authenticated ciphertext as canonical base64url blob bytes. */
export function encodeAccountSecretBlob(
    salt: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
): string {
    const header = blobHeader(salt, nonce, ciphertext.length);
    const bytes = new Uint8Array(header.length + ciphertext.length);
    try {
        bytes.set(header, 0);
        bytes.set(ciphertext, header.length);
        return encodeBase64Url(bytes);
    } finally {
        zeroBytes(header);
        zeroBytes(bytes);
    }
}

/** Decode and strictly validate one canonical account-secret blob. */
export function decodeAccountSecretBlob(blob: string): DecodedAccountSecretBlob {
    if (typeof blob !== "string" || blob.length === 0 || blob.length > 90_000) {
        throw invalidBlob();
    }

    let bytes: Uint8Array;
    try {
        bytes = decodeBase64Url(blob);
    } catch {
        throw invalidBlob();
    }

    try {
        if (
            bytes.length < BLOB_HEADER_BYTES + MINIMUM_PAYLOAD_BYTES + AEAD_TAG_BYTES ||
            bytes.length > MAXIMUM_BLOB_BYTES ||
            !equalBytes(bytes.subarray(0, BLOB_MAGIC.length), BLOB_MAGIC)
        ) {
            throw invalidBlob();
        }
        if (bytes[4] !== BLOB_VERSION) {
            throw new Error("Unsupported account secret blob version");
        }
        if (
            bytes[5] !== KDF_SCRYPT ||
            bytes[6] !== AEAD_AES_256_GCM ||
            bytes[7] !== SCRYPT_LOG_N ||
            bytes[8] !== SCRYPT_R ||
            bytes[9] !== SCRYPT_P
        ) {
            throw invalidBlob();
        }

        const ciphertextLength = new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint32(54, false);
        if (
            ciphertextLength !== bytes.length - BLOB_HEADER_BYTES ||
            ciphertextLength < MINIMUM_PAYLOAD_BYTES + AEAD_TAG_BYTES
        ) {
            throw invalidBlob();
        }

        return {
            associatedData: bytes.slice(0, BLOB_HEADER_BYTES),
            salt: bytes.slice(10, 42),
            nonce: bytes.slice(42, 54),
            ciphertext: bytes.slice(BLOB_HEADER_BYTES),
        };
    } finally {
        zeroBytes(bytes);
    }
}

/** Encode the ordered root-material payload encrypted inside the blob. */
export function encodeAccountSecretPayload(identityRoot: Uint8Array): Uint8Array {
    if (identityRoot.length !== IDENTITY_ROOT_BYTES) {
        throw new Error("Identity root secret must be 32 bytes");
    }
    const payload = new Uint8Array(MINIMUM_PAYLOAD_BYTES);
    payload[0] = PAYLOAD_VERSION;
    payload[1] = 1;
    payload[2] = IDENTITY_ROOT_FIELD;
    new DataView(payload.buffer, payload.byteOffset, payload.byteLength).setUint16(
        3,
        IDENTITY_ROOT_BYTES,
        false,
    );
    payload.set(identityRoot, 5);
    return payload;
}

/** Validate an ordered root-material payload and copy out its identity root. */
export function decodeAccountSecretPayload(payload: Uint8Array): Uint8Array {
    if (payload.length < MINIMUM_PAYLOAD_BYTES) {
        throw new Error("Invalid account secret payload");
    }
    if (payload[0] !== PAYLOAD_VERSION) {
        throw new Error("Unsupported account secret payload version");
    }

    const fieldCount = payload[1] ?? 0;
    let offset = 2;
    let previousType = 0;
    let identityRoot: Uint8Array | undefined;
    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    try {
        for (let index = 0; index < fieldCount; index += 1) {
            if (offset + PAYLOAD_FIELD_HEADER_BYTES > payload.length) {
                throw new Error("Invalid account secret payload");
            }
            const type = payload[offset] ?? 0;
            const length = view.getUint16(offset + 1, false);
            offset += PAYLOAD_FIELD_HEADER_BYTES;
            if (type <= previousType || length === 0 || offset + length > payload.length) {
                throw new Error("Invalid account secret payload");
            }
            if (type === IDENTITY_ROOT_FIELD) {
                if (length !== IDENTITY_ROOT_BYTES) {
                    throw new Error("Invalid account secret payload");
                }
                identityRoot = payload.slice(offset, offset + length);
            }
            previousType = type;
            offset += length;
        }
        if (offset !== payload.length || identityRoot === undefined) {
            throw new Error("Invalid account secret payload");
        }
        return identityRoot;
    } catch (error) {
        if (identityRoot !== undefined) zeroBytes(identityRoot);
        throw error;
    }
}
