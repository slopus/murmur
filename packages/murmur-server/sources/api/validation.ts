/**
 * Message and content size validation
 *
 * Limits to prevent abuse and resource exhaustion:
 * - Message blob: 10MB max (reasonable for encrypted files)
 * - Profile blob: 1MB max (should be enough for profile data)
 * - PreKey: 1KB max (just a public key)
 * - Signature: 1KB max (Ed25519 signature is 64 bytes)
 */

export const SIZE_LIMITS = {
    MESSAGE_BLOB: 10 * 1024 * 1024, // 10MB
    PROFILE_BLOB: 1 * 1024 * 1024, // 1MB
    PREKEY_PUBLIC: 1024, // 1KB
    SIGNATURE: 1024, // 1KB
    MESSAGE_ID: 256, // 256 bytes (cuid2 is ~24 chars)
    PUBLIC_KEY: 1024, // 1KB
} as const;

/**
 * Validate base64-encoded blob size
 */
export function validateBlobSize(base64String: string, maxSize: number, fieldName: string): void {
    // Base64 encoding increases size by ~33%, so we check the decoded size
    const decodedSize = (base64String.length * 3) / 4;

    if (decodedSize > maxSize) {
        throw new Error(
            `${fieldName} exceeds maximum size of ${formatBytes(maxSize)} ` +
            `(got ${formatBytes(decodedSize)})`
        );
    }
}

/**
 * Validate string field length
 */
export function validateStringLength(str: string, maxLength: number, fieldName: string): void {
    if (str.length > maxLength) {
        throw new Error(
            `${fieldName} exceeds maximum length of ${maxLength} characters ` +
            `(got ${str.length})`
        );
    }
}

/**
 * Validate array length
 */
export function validateArrayLength<T>(arr: T[], min: number, max: number, fieldName: string): void {
    if (arr.length < min) {
        throw new Error(`${fieldName} must contain at least ${min} items (got ${arr.length})`);
    }
    if (arr.length > max) {
        throw new Error(`${fieldName} must contain at most ${max} items (got ${arr.length})`);
    }
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Validate message data before processing
 */
export function validateMessageData(data: {
    messageId: string;
    blob: string;
    signature: string;
    recipientId: string;
}): void {
    validateStringLength(data.messageId, SIZE_LIMITS.MESSAGE_ID, 'messageId');
    validateBlobSize(data.blob, SIZE_LIMITS.MESSAGE_BLOB, 'blob');
    validateBlobSize(data.signature, SIZE_LIMITS.SIGNATURE, 'signature');
    validateStringLength(data.recipientId, SIZE_LIMITS.PUBLIC_KEY, 'recipientId');
}

/**
 * Validate profile data before processing
 */
export function validateProfileData(data: {
    profilePublicKey: string;
    profileKeySignature: string;
    encryptedProfile: string;
}): void {
    validateStringLength(data.profilePublicKey, SIZE_LIMITS.PUBLIC_KEY, 'profilePublicKey');
    validateBlobSize(data.profileKeySignature, SIZE_LIMITS.SIGNATURE, 'profileKeySignature');
    validateBlobSize(data.encryptedProfile, SIZE_LIMITS.PROFILE_BLOB, 'encryptedProfile');
}

/**
 * Validate prekey data before processing
 */
export function validatePreKeyData(data: {
    publicKey: string;
    signature: string;
}): void {
    validateStringLength(data.publicKey, SIZE_LIMITS.PREKEY_PUBLIC, 'publicKey');
    validateBlobSize(data.signature, SIZE_LIMITS.SIGNATURE, 'signature');
}
