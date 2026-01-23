import type { FastifyRequest, FastifyReply } from 'fastify';
import { verifyToken } from '@/utils/jwt';

/**
 * Authentication hook for Fastify routes
 * Extracts and validates JWT from Authorization header
 */
export async function authenticationHook(
    request: FastifyRequest,
    reply: FastifyReply
): Promise<void> {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return reply.status(401).send({ error: 'Missing or invalid authorization header' });
    }

    const token = authHeader.slice(7); // Remove 'Bearer ' prefix
    const payload = verifyToken(token);

    if (!payload) {
        return reply.status(401).send({ error: 'Invalid or expired token' });
    }

    // Attach user ID to request for use in route handlers
    (request as any).userId = payload.userId;
}

/**
 * Helper to get authenticated user ID from request
 */
export function getAuthUserId(request: FastifyRequest): string {
    return (request as any).userId;
}
