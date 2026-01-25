import { Registry, Counter, Histogram, Gauge } from 'prom-client';

/**
 * Prometheus metrics registry and collectors for Murmur Server
 */

// Create a new registry
export const register = new Registry();

// Default labels applied to all metrics
register.setDefaultLabels({
    app: 'murmur-server',
});

// ============================================================================
// HTTP Metrics
// ============================================================================

export const httpRequestsTotal = new Counter({
    name: 'murmur_http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code'],
    registers: [register],
});

export const httpRequestDuration = new Histogram({
    name: 'murmur_http_request_duration_seconds',
    help: 'HTTP request duration in seconds',
    labelNames: ['method', 'route', 'status_code'],
    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5],
    registers: [register],
});

// ============================================================================
// Message Metrics
// ============================================================================

export const messagesSentTotal = new Counter({
    name: 'murmur_messages_sent_total',
    help: 'Total number of messages sent',
    labelNames: ['status'], // 'success', 'invalid_signature', 'recipient_not_found', etc.
    registers: [register],
});

export const messagesDeliveredTotal = new Counter({
    name: 'murmur_messages_delivered_total',
    help: 'Total number of messages delivered (fetched by recipient)',
    registers: [register],
});

export const messagesAcknowledgedTotal = new Counter({
    name: 'murmur_messages_acknowledged_total',
    help: 'Total number of messages acknowledged (deleted)',
    registers: [register],
});

export const messagesExpiredTotal = new Counter({
    name: 'murmur_messages_expired_total',
    help: 'Total number of messages expired and deleted',
    registers: [register],
});

export const messageSize = new Histogram({
    name: 'murmur_message_size_bytes',
    help: 'Message size in bytes',
    buckets: [100, 1000, 10000, 100000, 1000000, 10000000],
    registers: [register],
});

export const undeliveredMessagesGauge = new Gauge({
    name: 'murmur_undelivered_messages',
    help: 'Current number of undelivered messages',
    registers: [register],
});

// ============================================================================
// Authentication Metrics
// ============================================================================

export const registrationsTotal = new Counter({
    name: 'murmur_registrations_total',
    help: 'Total number of user registrations',
    labelNames: ['status'],
    registers: [register],
});

export const loginsTotal = new Counter({
    name: 'murmur_logins_total',
    help: 'Total number of login attempts',
    labelNames: ['status'],
    registers: [register],
});

export const tokenRefreshesTotal = new Counter({
    name: 'murmur_token_refreshes_total',
    help: 'Total number of token refresh attempts',
    labelNames: ['status'],
    registers: [register],
});

// ============================================================================
// Profile Metrics
// ============================================================================

export const profileUpdatesTotal = new Counter({
    name: 'murmur_profile_updates_total',
    help: 'Total number of profile updates',
    labelNames: ['status'], // 'success', 'invalid_signature', 'size_limit_exceeded', etc.
    registers: [register],
});

// ============================================================================
// PreKey Metrics
// ============================================================================

export const preKeysUploadedTotal = new Counter({
    name: 'murmur_prekeys_uploaded_total',
    help: 'Total number of prekeys uploaded',
    labelNames: ['status'], // 'success', 'invalid_signature', 'size_limit_exceeded', etc.
    registers: [register],
});

export const preKeysAllocatedTotal = new Counter({
    name: 'murmur_prekeys_allocated_total',
    help: 'Total number of prekeys allocated',
    labelNames: ['type'], // 'signed' or 'onetime'
    registers: [register],
});

export const unallocatedPreKeysGauge = new Gauge({
    name: 'murmur_unallocated_prekeys',
    help: 'Current number of unallocated one-time prekeys',
    registers: [register],
});

// ============================================================================
// SSE Connection Metrics
// ============================================================================

export const sseConnectionsTotal = new Counter({
    name: 'murmur_sse_connections_total',
    help: 'Total number of SSE connections established',
    registers: [register],
});

export const sseActiveConnections = new Gauge({
    name: 'murmur_sse_active_connections',
    help: 'Current number of active SSE connections',
    registers: [register],
});

export const sseMessagesSent = new Counter({
    name: 'murmur_sse_messages_sent_total',
    help: 'Total number of messages sent via SSE',
    labelNames: ['event_type'], // 'connected', 'message', 'ping'
    registers: [register],
});

// ============================================================================
// Rate Limiting Metrics
// ============================================================================

export const rateLimitHitsTotal = new Counter({
    name: 'murmur_rate_limit_hits_total',
    help: 'Total number of requests that hit rate limits',
    labelNames: ['route'],
    registers: [register],
});

// ============================================================================
// Database Metrics
// ============================================================================

export const dbQueryDuration = new Histogram({
    name: 'murmur_db_query_duration_seconds',
    help: 'Database query duration in seconds',
    labelNames: ['operation'],
    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
    registers: [register],
});

export const dbConnectionsActive = new Gauge({
    name: 'murmur_db_connections_active',
    help: 'Current number of active database connections',
    registers: [register],
});

// ============================================================================
// Cleanup Worker Metrics
// ============================================================================

export const cleanupRunsTotal = new Counter({
    name: 'murmur_cleanup_runs_total',
    help: 'Total number of cleanup worker runs',
    labelNames: ['status'], // 'success' or 'failure'
    registers: [register],
});

export const cleanupLastRun = new Gauge({
    name: 'murmur_cleanup_last_run_timestamp',
    help: 'Timestamp of last cleanup run (Unix time)',
    registers: [register],
});

// ============================================================================
// System Metrics
// ============================================================================

export const uptimeSeconds = new Gauge({
    name: 'murmur_uptime_seconds',
    help: 'Server uptime in seconds',
    registers: [register],
});

const startTime = Date.now();
setInterval(() => {
    uptimeSeconds.set((Date.now() - startTime) / 1000);
}, 10000); // Update every 10 seconds
