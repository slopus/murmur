import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

export type Fastify = FastifyInstance<any, any, any, any, ZodTypeProvider>;
