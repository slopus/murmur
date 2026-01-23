import rateLimit from '@fastify/rate-limit';
import type { FastifyInstance } from 'fastify';
import { rateLimitHitsTotal } from '@/metrics/prometheus';

/**
 * Rate limiting configuration for Murmur Server
 *
 * Different limits for different endpoint categories:
 * - Public auth endpoints: 10 req/min
 * - Message sending: 100 req/hour per user
 * - Message fetching: 1000 req/hour per user
 * - PreKey operations: 50 req/hour per user
 */

export async function registerRateLimiting(app: FastifyInstance) {
    await app.register(rateLimit, {
        global: false, // Don't apply globally, we'll configure per-route
        redis: process.env.REDIS_URL ? undefined : undefined, // Use in-memory for now
        nameSpace: 'murmur-rate-limit:',
        onExceeded: (req) => {
            const route = req.routeOptions?.url || 'unknown';
            rateLimitHitsTotal.inc({ route });
        },
    });
}

/**
 * Rate limit configurations for different route groups
 */
export const rateLimitConfigs = {
    // Public authentication endpoints (prevent brute force)
    auth: {
        max: 10, // 10 requests
        timeWindow: '1 minute',
        errorResponseBuilder: () => ({
            error: 'Too many authentication attempts. Please try again later.',
            retryAfter: 60,
        }),
    },

    // Message sending (prevent spam)
    messageSend: {
        max: 100, // 100 messages
        timeWindow: '1 hour',
        keyGenerator: (req: any) => {
            // Rate limit per user
            return req.user?.id || req.ip;
        },
        errorResponseBuilder: () => ({
            error: 'Message sending rate limit exceeded. Max 100 messages per hour.',
            retryAfter: 3600,
        }),
    },

    // Message fetching (prevent abuse)
    messageFetch: {
        max: 1000, // 1000 requests
        timeWindow: '1 hour',
        keyGenerator: (req: any) => {
            return req.user?.id || req.ip;
        },
        errorResponseBuilder: () => ({
            error: 'Message fetching rate limit exceeded. Max 1000 requests per hour.',
            retryAfter: 3600,
        }),
    },

    // PreKey operations (prevent prekey exhaustion attacks)
    preKey: {
        max: 50, // 50 requests
        timeWindow: '1 hour',
        keyGenerator: (req: any) => {
            return req.user?.id || req.ip;
        },
        errorResponseBuilder: () => ({
            error: 'PreKey operation rate limit exceeded. Max 50 requests per hour.',
            retryAfter: 3600,
        }),
    },

    // Profile operations (prevent spam)
    profile: {
        max: 200, // 200 requests
        timeWindow: '1 hour',
        keyGenerator: (req: any) => {
            return req.user?.id || req.ip;
        },
        errorResponseBuilder: () => ({
            error: 'Profile operation rate limit exceeded. Max 200 requests per hour.',
            retryAfter: 3600,
        }),
    },
};
