import fastify from "fastify";
import { register } from "./prometheus";
import { db } from "@/db";
import { log } from "@/log";
import { onShutdown } from "@/shutdown";
import { events } from "@/events";
import {
    undeliveredMessagesGauge,
    unallocatedPreKeysGauge,
    dbConnectionsActive,
} from "./prometheus";

/**
 * Start metrics and health check server on separate port
 *
 * Endpoints:
 * - GET /metrics - Prometheus metrics
 * - GET /health - Health check with dependency status
 */
export async function startMetricsServer() {
    const app = fastify({
        logger: false, // Separate server, minimal logging
    });

    // Prometheus metrics endpoint
    app.get("/metrics", async (_request, reply) => {
        try {
            // Update gauge metrics before serving
            await updateGaugeMetrics();

            const metrics = await register.metrics();
            reply.header("Content-Type", register.contentType);
            reply.send(metrics);
        } catch (error) {
            log(`Metrics error: ${error}`);
            reply.status(500).send({ error: "Failed to collect metrics" });
        }
    });

    // Health check endpoint
    app.get("/health", async (_request, reply) => {
        const health = {
            status: "healthy",
            timestamp: Date.now(),
            dependencies: {
                postgres: "unknown",
                redis: "unknown",
            },
        };

        try {
            // Check PostgreSQL
            await db.$queryRaw`SELECT 1`;
            health.dependencies.postgres = "connected";
        } catch (error) {
            health.status = "unhealthy";
            health.dependencies.postgres = "disconnected";
        }

        // Check Redis via events singleton
        try {
            if (events) {
                health.dependencies.redis = "connected";
            } else {
                health.dependencies.redis = "disconnected";
                health.status = "unhealthy";
            }
        } catch (error) {
            health.dependencies.redis = "disconnected";
            health.status = "unhealthy";
        }

        const statusCode = health.status === "healthy" ? 200 : 503;
        reply.status(statusCode).send(health);
    });

    // Liveness probe (simpler, always returns OK if server is running)
    app.get("/liveness", async (_request, reply) => {
        reply.send({ status: "alive", timestamp: Date.now() });
    });

    // Readiness probe (checks if server is ready to accept traffic)
    app.get("/readiness", async (_request, reply) => {
        try {
            await db.$queryRaw`SELECT 1`;
            reply.send({ status: "ready", timestamp: Date.now() });
        } catch (error) {
            reply.status(503).send({ status: "not ready", timestamp: Date.now() });
        }
    });

    // Start metrics server on separate port
    const port = process.env.METRICS_PORT ? parseInt(process.env.METRICS_PORT, 10) : 9090;
    await app.listen({ port, host: "0.0.0.0" });
    log(`Metrics server started on port ${port}`);

    onShutdown("metrics", async () => {
        await app.close();
    });
}

/**
 * Update gauge metrics that track current state
 */
async function updateGaugeMetrics() {
    try {
        // Count undelivered messages
        const undeliveredCount = await db.message.count({
            where: {
                deliveredAt: null,
                expiresAt: {
                    gt: new Date(),
                },
            },
        });
        undeliveredMessagesGauge.set(undeliveredCount);

        // Count unallocated one-time prekeys
        const unallocatedCount = await db.preKey.count({
            where: {
                oneTime: true,
                allocatedTo: null,
            },
        });
        unallocatedPreKeysGauge.set(unallocatedCount);

        // Get active database connections from Prisma metrics
        const metrics = await db.$metrics.json();
        const poolSize = metrics.counters.find((c: any) => c.key === "prisma_client_queries_total");
        if (poolSize) {
            dbConnectionsActive.set(poolSize.value);
        }
    } catch (error) {
        // Silently fail gauge updates to not break metrics endpoint
        log(`Failed to update gauge metrics: ${error}`);
    }
}
