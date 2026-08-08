# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM oven/bun:1.3.6 AS bun

FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS build

ARG TARGETARCH

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

RUN corepack enable

WORKDIR /workspace

COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/murmur/package.json packages/murmur/package.json
COPY packages/murmur-relay/package.json packages/murmur-relay/package.json

RUN pnpm install --frozen-lockfile --filter @slopus/murmur-relay...

COPY packages/murmur-relay packages/murmur-relay

RUN case "$TARGETARCH" in \
        amd64) bun_target=bun-linux-x64 ;; \
        arm64) bun_target=bun-linux-arm64 ;; \
        *) echo "Unsupported relay image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && pnpm --filter @slopus/murmur-relay build:binary -- --target "$bun_target"

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /workspace/packages/murmur-relay/dist/murmur-relay /usr/local/bin/murmur-relay

RUN mkdir --parents /data \
    && chown 65532:65532 /data

USER 65532:65532
WORKDIR /data

ENV HOST=0.0.0.0
ENV PORT=8787
ENV MURMUR_RELAY_STORE=sqlite
ENV MURMUR_RELAY_DB=/data/murmur-relay.sqlite

VOLUME ["/data"]
EXPOSE 8787
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/murmur-relay"]