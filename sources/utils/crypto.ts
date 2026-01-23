import nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

const encodeBase64 = naclUtil.encodeBase64;
const decodeBase64 = naclUtil.decodeBase64;

/**
 * Verify a NaCl signature
 * @param message - The message that was signed (as UTF-8 string or Uint8Array)
 * @param signature - The signature in base64 format
 * @param publicKey - The public key in base64 format
 * @returns true if signature is valid, false otherwise
 */
export function verifySignature(
    message: string | Uint8Array,
    signature: string,
    publicKey: string
): boolean {
    try {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;
        const signatureBytes = decodeBase64(signature);
        const publicKeyBytes = decodeBase64(publicKey);

        return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
    } catch (error) {
        return false;
    }
}

/**
 * Sign a message with a private key
 * @param message - The message to sign
 * @param privateKey - The private key in base64 format
 * @returns The signature in base64 format
 */
export function signMessage(message: string | Uint8Array, privateKey: string): string {
    const messageBytes = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;
    const privateKeyBytes = decodeBase64(privateKey);

    const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
    return encodeBase64(signature);
}

/**
 * Generate a new NaCl key pair
 * @returns Object with publicKey and privateKey in base64 format
 */
export function generateKeyPair(): { publicKey: string; privateKey: string } {
    const keyPair = nacl.sign.keyPair();
    return {
        publicKey: encodeBase64(keyPair.publicKey),
        privateKey: encodeBase64(keyPair.secretKey),
    };
}

/**
 * Validate that a string is a valid base64-encoded public key
 */
export function isValidPublicKey(publicKey: string): boolean {
    try {
        const bytes = decodeBase64(publicKey);
        return bytes.length === nacl.sign.publicKeyLength;
    } catch {
        return false;
    }
}
