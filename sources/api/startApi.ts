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
import { profileRoutes } from './routes/v1/profile';
import { messageRoutes } from './routes/v1/messages';
import { Fastify } from '@/types';

export async function startApi() {
    // Start API
    const app = fastify({ loggerInstance: logger })
        .withTypeProvider<ZodTypeProvider>() as unknown as Fastify;

    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    app.register(import('@fastify/cors'), {
        origin: '*',
        allowedHeaders: '*',
        methods: ['GET', 'POST', 'DELETE']
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

    // Authenticated routes under /v1
    await app.register(async function (authenticatedApp) {
        // Apply authentication hook to all routes in this group
        authenticatedApp.addHook('onRequest', async (request, reply) => {
            await authenticationHook(request, reply);
        });

        // Register authenticated routes
        await profileRoutes(authenticatedApp);
        await messageRoutes(authenticatedApp);
    });

    // Start HTTP
    const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
    await app.listen({ port, host: '0.0.0.0' });

    onShutdown('api', async () => {
        await app.close();
    });
}
