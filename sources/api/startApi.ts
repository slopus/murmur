import fastify from 'fastify';
import { logger } from '@/log';
import { onShutdown } from '@/shutdown';
import {
    serializerCompiler,
    validatorCompiler,
    type ZodTypeProvider
} from 'fastify-type-provider-zod';
import { authenticationHook } from './auth';
import { authRoutes } from './routes/v1/auth';
import { profileRoutes, publicProfileRoutes } from './routes/v1/profile';
import { messageRoutes } from './routes/v1/messages';
import { preKeyRoutes } from './routes/v1/prekeys';
import { Fastify } from '@/types';
import { registerRateLimiting } from './rateLimit';
import { httpRequestsTotal, httpRequestDuration } from '@/metrics/prometheus';

export async function startApi() {
    // Start API
    const app = fastify({ loggerInstance: logger })
        .withTypeProvider<ZodTypeProvider>() as unknown as Fastify;

    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    // Register rate limiting
    await registerRateLimiting(app);

    // Metrics middleware - track all HTTP requests
    app.addHook('onRequest', async (request) => {
        (request as any).startTime = Date.now();
    });

    app.addHook('onResponse', async (request, reply) => {
        const duration = (Date.now() - (request as any).startTime) / 1000;
        const route = request.routeOptions?.url || 'unknown';
        const method = request.method;
        const statusCode = reply.statusCode.toString();

        httpRequestsTotal.inc({ method, route, status_code: statusCode });
        httpRequestDuration.observe({ method, route, status_code: statusCode }, duration);
    });

    // Health check
    app.get('/health', { logLevel: 'silent' }, function (_request, reply) {
        reply.send('OK');
    });

    // Root endpoint
    app.get('/', { logLevel: 'silent' }, function (_request, reply) {
        reply.send('Murmur Server - Encrypted Message Transfer');
    });

    // Public routes (no authentication)
    await authRoutes(app);
    await publicProfileRoutes(app);

    // Authenticated routes under /v1
    await app.register(async function (authenticatedApp) {
        // Apply authentication hook to all routes in this group
        authenticatedApp.addHook('onRequest', async (request, reply) => {
            await authenticationHook(request, reply);
        });

        // Register authenticated routes
        await profileRoutes(authenticatedApp);
        await messageRoutes(authenticatedApp);
        await preKeyRoutes(authenticatedApp);
    });

    // Start HTTP
    const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
    await app.listen({ port, host: '0.0.0.0' });

    onShutdown('api', async () => {
        await app.close();
    });
}
