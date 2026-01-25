# Stage 1: Building the application
FROM node:20 AS builder

WORKDIR /app

# Copy package.json and yarn.lock
COPY package.json yarn.lock ./
COPY ./prisma ./prisma

# Install dependencies
RUN yarn install --frozen-lockfile --ignore-engines

# Copy the rest of the application code
COPY ./tsconfig.json ./tsconfig.json
COPY ./vitest.config.ts ./vitest.config.ts
COPY ./sources ./sources

# Build the application
RUN yarn build

# Generate Prisma client
RUN yarn generate

# Stage 2: Runtime
FROM node:20 AS runner

WORKDIR /app

# Set environment to production
ENV NODE_ENV=production

# Copy necessary files from the builder stage
COPY --from=builder /app/tsconfig.json ./tsconfig.json
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/yarn.lock ./yarn.lock
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/sources ./sources
COPY --from=builder /app/prisma ./prisma

# Expose the port the app will run on
EXPOSE 3000

# Command to run the application
CMD ["yarn", "start"]
