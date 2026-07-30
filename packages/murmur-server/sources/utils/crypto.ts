import { ed25519 } from "@noble/curves/ed25519";

/**
 * Base64 encoding/decoding utilities
 */
function encodeBase64(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64");
}

function decodeBase64(str: string): Uint8Array {
    return new Uint8Array(Buffer.from(str, "base64"));
}

/**
 * Verify an Ed25519 signature
 * @param message - The message that was signed (as UTF-8 string or Uint8Array)
 * @param signature - The signature in base64 format
 * @param publicKey - The public key in base64 format
 * @returns true if signature is valid, false otherwise
 */
export function verifySignature(
    message: string | Uint8Array,
    signature: string,
    publicKey: string,
): boolean {
    try {
        const messageBytes =
            typeof message === "string" ? new TextEncoder().encode(message) : message;
        const signatureBytes = decodeBase64(signature);
        const publicKeyBytes = decodeBase64(publicKey);

        return ed25519.verify(signatureBytes, messageBytes, publicKeyBytes);
    } catch (error) {
        return false;
    }
}

/**
 * Sign a message with a private key
 * @param message - The message to sign
 * @param privateKey - The private key in base64 format (32-byte seed)
 * @returns The signature in base64 format
 */
export function signMessage(message: string | Uint8Array, privateKey: string): string {
    const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
    const privateKeyBytes = decodeBase64(privateKey);

    const signature = ed25519.sign(messageBytes, privateKeyBytes);
    return encodeBase64(signature);
}

/**
 * Generate a new Ed25519 key pair
 * @returns Object with publicKey and privateKey in base64 format
 */
export function generateKeyPair(): { publicKey: string; privateKey: string } {
    const privateKey = ed25519.utils.randomSecretKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return {
        publicKey: encodeBase64(publicKey),
        privateKey: encodeBase64(privateKey),
    };
}

/**
 * Validate that a string is a valid public key encoding.
 */
export function isValidPublicKey(publicKey: string): boolean {
    try {
        const bytes = decodeBase64(publicKey);
        return bytes.length === 32; // Ed25519 public key is 32 bytes
    } catch {
        return false;
    }
}

/**
 * Normalize a public key to internal base64.
 * Throws if the key is invalid or the decoded length is not 32 bytes.
 */
export function normalizePublicKey(publicKey: string): string {
    const bytes = decodeBase64(publicKey);
    if (bytes.length !== 32) {
        throw new Error("Invalid public key format");
    }
    return encodeBase64(bytes);
}

/**
 * Convert an internal base64 public key to the external base64 format.
 */
export function publicKeyToExternal(publicKey: string): string {
    const bytes = decodeBase64(publicKey);
    if (bytes.length !== 32) {
        throw new Error("Invalid public key format");
    }
    return encodeBase64(bytes);
}
