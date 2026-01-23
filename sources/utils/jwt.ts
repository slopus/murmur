import * as privacyKit from 'privacy-kit';

const JWT_SEED = process.env.JWT_SEED || 'dev-seed-change-in-production';
const JWT_PUBLIC_KEY_BASE64 = process.env.JWT_PUBLIC_KEY;

let tokenGenerator: Awaited<ReturnType<typeof privacyKit.createPersistentTokenGenerator>> | null = null;
let tokenVerifier: Awaited<ReturnType<typeof privacyKit.createPersistentTokenVerifier>> | null = null;

/**
 * Initialize the token generator and verifier
 * This should be called once at startup
 */
export async function initializeJWT(): Promise<void> {
    // Initialize generator with seed
    tokenGenerator = await privacyKit.createPersistentTokenGenerator({
        service: 'murmur-auth',
        seed: JWT_SEED,
    });

    // Get public key from generator or environment
    const publicKeyBytes = JWT_PUBLIC_KEY_BASE64
        ? privacyKit.decodeBase64(JWT_PUBLIC_KEY_BASE64)
        : tokenGenerator.publicKey;

    // Initialize verifier with public key
    tokenVerifier = await privacyKit.createPersistentTokenVerifier({
        service: 'murmur-auth',
        publicKey: publicKeyBytes,
    });
}

export interface JWTPayload {
    userId: string; // Identity public key
    user?: string | null;
    uuid?: string | null;
}

/**
 * Generate a JWT token for a user
 * privacy-kit tokens include both access tokens (24h expiration) and refresh tokens
 * The tokens returned are already in the format "access.refresh" which is a single string
 */
export async function generateToken(userId: string): Promise<string> {
    if (!tokenGenerator) {
        throw new Error('JWT not initialized. Call initializeJWT() first.');
    }

    // privacy-kit automatically handles refresh tokens and 24h expiration
    const token = await tokenGenerator.new({
        user: userId,
    });

    return token;
}

/**
 * Verify and decode a JWT token
 * @returns The payload if valid, null if invalid
 */
export async function verifyToken(token: string): Promise<JWTPayload | null> {
    if (!tokenVerifier) {
        throw new Error('JWT not initialized. Call initializeJWT() first.');
    }

    try {
        const result = await tokenVerifier.verify(token);

        if (!result || !result.user) {
            return null;
        }

        return {
            userId: result.user,
            user: result.user,
            uuid: result.uuid,
        };
    } catch {
        return null;
    }
}
