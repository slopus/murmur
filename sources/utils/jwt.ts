import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const JWT_EXPIRATION = '30d'; // 30 days

export interface JWTPayload {
    userId: string; // Identity public key
    iat?: number;
    exp?: number;
}

/**
 * Generate a JWT token for a user
 */
export function generateToken(userId: string): string {
    const payload: JWTPayload = { userId };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRATION });
}

/**
 * Verify and decode a JWT token
 * @returns The payload if valid, null if invalid
 */
export function verifyToken(token: string): JWTPayload | null {
    try {
        const payload = jwt.verify(token, JWT_SECRET) as JWTPayload;
        return payload;
    } catch {
        return null;
    }
}
