import * as privacyKit from 'privacy-kit';

const JWT_SEED = process.env.JWT_SEED || 'dev-seed-change-in-production';
const ACCESS_TOKEN_TTL_MS =
    Number.parseInt(process.env.ACCESS_TOKEN_TTL_MS ?? '', 10) || 1000 * 60 * 60 * 24; // 24 hours in ms
const REFRESH_TOKEN_SERVICE = 'murmur-refresh';
const ACCESS_TOKEN_SERVICE = 'murmur-access';

let refreshTokenGenerator: Awaited<ReturnType<typeof privacyKit.createPersistentTokenGenerator>> | null = null;
let refreshTokenVerifier: Awaited<ReturnType<typeof privacyKit.createPersistentTokenVerifier>> | null = null;
let accessTokenGenerator: Awaited<ReturnType<typeof privacyKit.createEphemeralTokenGenerator>> | null = null;
let accessTokenVerifier: Awaited<ReturnType<typeof privacyKit.createEphemeralTokenVerifier>> | null = null;

/**
 * Initialize the token generators and verifiers
 * This should be called once at startup
 */
export async function initializeJWT(): Promise<void> {
    // Initialize refresh token generator (persistent, long-lived)
    refreshTokenGenerator = await privacyKit.createPersistentTokenGenerator({
        service: REFRESH_TOKEN_SERVICE,
        seed: JWT_SEED,
    });

    // Initialize refresh token verifier using public key from generator
    refreshTokenVerifier = await privacyKit.createPersistentTokenVerifier({
        service: REFRESH_TOKEN_SERVICE,
        publicKey: refreshTokenGenerator.publicKey,
    });

    // Initialize access token generator (ephemeral, short-lived)
    accessTokenGenerator = await privacyKit.createEphemeralTokenGenerator({
        service: ACCESS_TOKEN_SERVICE,
        seed: JWT_SEED,
        ttl: ACCESS_TOKEN_TTL_MS,
    });

    // Initialize access token verifier using public key from generator
    accessTokenVerifier = await privacyKit.createEphemeralTokenVerifier({
        service: ACCESS_TOKEN_SERVICE,
        publicKey: accessTokenGenerator.publicKey,
    });
}

export interface JWTPayload {
    userId: string; // Identity public key
    user?: string | null;
    uuid?: string | null;
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
}

/**
 * Generate a token pair (access + refresh) for a user
 * @param userId - The user ID to generate tokens for
 * @returns Object with accessToken (configurable expiry) and refreshToken (long-lived)
 */
export async function generateToken(userId: string): Promise<TokenPair> {
    if (!accessTokenGenerator || !refreshTokenGenerator) {
        throw new Error('JWT not initialized. Call initializeJWT() first.');
    }

    const [accessToken, refreshToken] = await Promise.all([
        accessTokenGenerator.new({ user: userId }),
        refreshTokenGenerator.new({ user: userId }),
    ]);

    return {
        accessToken,
        refreshToken,
    };
}

/**
 * Verify and decode an access token
 * @returns The payload if valid, null if invalid or expired
 */
export async function verifyAccessToken(token: string): Promise<JWTPayload | null> {
    if (!accessTokenVerifier) {
        throw new Error('JWT not initialized. Call initializeJWT() first.');
    }

    try {
        const result = await accessTokenVerifier.verify(token);

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

/**
 * Verify and decode a refresh token
 * @returns The payload if valid, null if invalid
 */
export async function verifyRefreshToken(token: string): Promise<JWTPayload | null> {
    if (!refreshTokenVerifier) {
        throw new Error('JWT not initialized. Call initializeJWT() first.');
    }

    try {
        const result = await refreshTokenVerifier.verify(token);

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

/**
 * Refresh an access token using a valid refresh token
 * @param refreshToken - The refresh token
 * @returns New access token if refresh token is valid, null otherwise
 */
export async function refreshAccessToken(refreshToken: string): Promise<string | null> {
    const payload = await verifyRefreshToken(refreshToken);

    if (!payload || !payload.userId) {
        return null;
    }

    if (!accessTokenGenerator) {
        throw new Error('JWT not initialized. Call initializeJWT() first.');
    }

    // Generate new access token with same user ID
    const accessToken = await accessTokenGenerator.new({
        user: payload.userId,
    });

    return accessToken;
}

/**
 * Legacy function for backward compatibility
 * @deprecated Use verifyAccessToken instead
 */
export async function verifyToken(token: string): Promise<JWTPayload | null> {
    return verifyAccessToken(token);
}
