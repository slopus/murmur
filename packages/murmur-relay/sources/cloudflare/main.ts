import { verifyRelaySessionToken } from "../session/index.js";
import { RelayError } from "../protocol/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { relaySessionTokenFromWebSocketProtocols } from "../websocket/index.js";
import { MurmurFanoutDurableObject } from "./fanoutDurableObject.js";
import { MurmurInboxDurableObject } from "./inboxDurableObject.js";
import { parseTokenSecret } from "./impl/cloudflareCodec.js";
import type { MurmurCloudflareEnvironment } from "./types.js";

export { MurmurFanoutDurableObject, MurmurInboxDurableObject };

function json(body: unknown, status: number): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

/** Public Worker ingress; Durable Objects themselves are never exposed by name. */
export default {
    async fetch(request: Request, environment: MurmurCloudflareEnvironment): Promise<Response> {
        const url = new URL(request.url);
        if (request.method === "GET" && url.pathname === "/health") {
            return json({ ok: true }, 200);
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
