import { LocalDirectoryTicketIssuer } from "../directory/index.js";
import { createRelaySessionFetchHandler, verifyRelaySessionToken } from "../session/index.js";
import { RelayError } from "../protocol/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { relaySessionTokenFromWebSocketProtocols } from "../websocket/index.js";
import { MurmurFanoutDurableObject } from "./fanoutDurableObject.js";
import { MurmurInboxDurableObject } from "./inboxDurableObject.js";
import { deriveCloudflareDirectoryTicketSecret, parseTokenSecret } from "./impl/cloudflareCodec.js";
import type { MurmurCloudflareEnvironment } from "./types.js";
import {
    createWorkOSAccessTokenVerifier,
    type AuthenticateWorkOSAccessToken,
} from "./workosAuthentication.js";

export { MurmurFanoutDurableObject, MurmurInboxDurableObject };

const DIRECTORY_TICKET_TTL_MILLISECONDS = 60_000;
const DIRECTORY_TICKET_CLAIM_BUDGET = 8;
const FANOUT_OBJECT_NAME = "global-v1";

export interface MurmurCloudflareWorkerOptions {
    readonly authenticateAccessToken?: AuthenticateWorkOSAccessToken;
}

interface CachedWorkOSVerifier {
    readonly clientId: string;
    readonly issuer: string | undefined;
    readonly verify: AuthenticateWorkOSAccessToken;
}

let cachedWorkOSVerifier: CachedWorkOSVerifier | undefined;

function json(body: unknown, status: number): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

function bearerToken(request: Request): string | undefined {
    return /^Bearer[\t ]+([^\t ]+)$/i.exec(request.headers.get("authorization") ?? "")?.[1];
}

function accessTokenVerifier(
    environment: MurmurCloudflareEnvironment,
    options: MurmurCloudflareWorkerOptions,
): AuthenticateWorkOSAccessToken {
    if (options.authenticateAccessToken !== undefined) return options.authenticateAccessToken;
    const clientId = environment.WORKOS_CLIENT_ID?.trim();
    if (!clientId) throw new Error("WORKOS_CLIENT_ID is required");
    const issuer = environment.WORKOS_ISSUER?.trim() || undefined;
    if (
        cachedWorkOSVerifier === undefined ||
        cachedWorkOSVerifier.clientId !== clientId ||
        cachedWorkOSVerifier.issuer !== issuer
    ) {
        cachedWorkOSVerifier = {
            clientId,
            issuer,
            verify: createWorkOSAccessTokenVerifier(clientId, issuer),
        };
    }
    return cachedWorkOSVerifier.verify;
}

async function authenticatedUserId(
    request: Request,
    environment: MurmurCloudflareEnvironment,
    options: MurmurCloudflareWorkerOptions,
): Promise<string | undefined> {
    const token = bearerToken(request);
    if (token === undefined) return undefined;
    try {
        return (await accessTokenVerifier(environment, options)(token)).userId;
    } catch {
        return undefined;
    }
}

/** Public Worker ingress; Durable Objects themselves are never exposed by name. */
export function createMurmurCloudflareWorker(options: MurmurCloudflareWorkerOptions = {}) {
    return {
        async fetch(request: Request, environment: MurmurCloudflareEnvironment): Promise<Response> {
            const url = new URL(request.url);
            if (request.method === "GET" && url.pathname === "/health") {
                return json({ ok: true }, 200);
            }
            if (request.method === "POST" && url.pathname === "/v2/session") {
                const userId = await authenticatedUserId(request, environment, options);
                if (userId === undefined) return json({ error: "unauthorized" }, 401);
                return createRelaySessionFetchHandler({
                    tokenSecret: parseTokenSecret(environment.MURMUR_RELAY_TOKEN_SECRET),
                    authorize: async () => ({
                        admissionPrincipal: userId,
                        endpoint: environment.MURMUR_RELAY_ENDPOINT,
                    }),
                })(request);
            }
            if (request.method === "POST" && url.pathname === "/v2/directory-ticket") {
                const userId = await authenticatedUserId(request, environment, options);
                if (userId === undefined) return json({ error: "unauthorized" }, 401);
                const fanoutId = environment.MURMUR_FANOUT.idFromName(FANOUT_OBJECT_NAME);
                const admission = await environment.MURMUR_FANOUT.get(fanoutId).fetch(
                    new Request("https://murmur.internal/v2/directory-ticket/authorize", {
                        method: "POST",
                        headers: { "content-type": "application/json" },
                        body: JSON.stringify({ admissionPrincipal: userId }),
                    }),
                );
                if (admission.status === 429) {
                    return new Response(await admission.text(), {
                        status: 429,
                        headers: {
                            "content-type": "application/json; charset=utf-8",
                            "cache-control": "no-store",
                        },
                    });
                }
                if (!admission.ok) return json({ error: "unavailable" }, 503);
                const expiresAt = Date.now() + DIRECTORY_TICKET_TTL_MILLISECONDS;
                const issuer = new LocalDirectoryTicketIssuer({
                    issuer: "murmur-cloudflare-directory",
                    secretKey: deriveCloudflareDirectoryTicketSecret(
                        environment.MURMUR_RELAY_TOKEN_SECRET,
                    ),
                });
                return json(
                    {
                        version: 1,
                        ticket: encodeBase64Url(
                            issuer.issue({
                                expiresAt,
                                claimBudget: DIRECTORY_TICKET_CLAIM_BUDGET,
                            }),
                        ),
                        expiresAt,
                    },
                    200,
                );
            }
            if (
                request.method !== "GET" ||
                url.pathname !== "/v2/connect" ||
                request.headers.get("upgrade")?.toLowerCase() !== "websocket"
            ) {
                return json({ error: "not_found" }, 404);
            }
            try {
                const token = relaySessionTokenFromWebSocketProtocols(
                    request.headers.get("sec-websocket-protocol"),
                );
                const claims = verifyRelaySessionToken(
                    parseTokenSecret(environment.MURMUR_RELAY_TOKEN_SECRET),
                    token,
                    { expectedEndpoint: environment.MURMUR_RELAY_ENDPOINT },
                );
                const id = environment.MURMUR_INBOXES.idFromName(encodeBase64Url(claims.device));
                return environment.MURMUR_INBOXES.get(id).fetch(request);
            } catch (error: unknown) {
                if (error instanceof RelayError) return json(error.body, error.status);
                return json({ error: "internal" }, 500);
            }
        },
    };
}

export default createMurmurCloudflareWorker();
