# Deployment Guide

This document covers how to deploy Murmur in development and production.

## Components

Murmur deployment consists of:

- Murmur server (`packages/murmur-server`)
- PostgreSQL (persistent storage)
- Redis (event bus for realtime notifications)

## Local Development

From the repo root:

```bash
cd packages/murmur-server
cp .env.example .env
yarn install
yarn migrate
yarn start
```

Redis and Postgres can be run with Docker. The server expects `DATABASE_URL`
and `REDIS_URL` to be reachable from the process.

## Production (Docker Compose)

The server package includes `docker-compose.yml` and `Dockerfile`. A typical
workflow:

```bash
cd packages/murmur-server
cp .env.example .env
docker-compose up -d
```

Then run migrations once:

```bash
yarn migrate
```

## Environment Variables

Server runtime:

- `DATABASE_URL`: PostgreSQL connection string (required).
- `REDIS_URL`: Redis connection string (required for realtime).
- `JWT_SEED`: secret seed for token generation (required in production).
- `ACCESS_TOKEN_TTL_MS`: access token TTL in milliseconds (default 24h).
- `EVENT_STREAM_MAXLEN`: Redis stream trim length (default 10000).
- `PORT`: API port (default 3000).
- `METRICS_PORT`: Prometheus metrics port (default 9090).
- `LOG_LEVEL`: pino log level (default `info`).

## Realtime (SSE) Requirements

- Clients connect to `/v1/messages/stream` and keep the connection open.
- The server emits heartbeat pings every 30 seconds.
- Load balancers should allow long-lived connections and not buffer SSE.
- Sticky sessions are not required, but the client must reconnect on drop.

## Event Bus (Redis Streams)

The EventBus uses Redis Streams in broadcast mode:

- Each node reads the stream independently using `XREAD`.
- Nodes start at the current stream tail on boot.
- All nodes receive all events (fan-out).
- Stream length is capped by `EVENT_STREAM_MAXLEN`.

Because the stream is trimmed, SSE events should be treated as hints. The
client always follows up with `sync` to fetch messages from the database.

## Scaling Notes

- Multiple server instances can run behind a load balancer.
- Redis must be shared across all instances.
- Postgres is the source of truth for inbox messages.
- SSE connections are per instance; clients reconnect automatically.

## Data Retention

- Messages expire after 30 days.
- A cleanup worker runs hourly to delete expired messages.
