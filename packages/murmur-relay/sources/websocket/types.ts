import type { RelayService } from "../relay/index.js";
import type { RelaySessionClaims } from "../session/index.js";

/** Host-neutral accepted WebSocket used by the relay session engine. */
export interface RelayWebSocketPeer {
    send(message: string): void;
    close(code?: number, reason?: string): void;
}

/** Construction policy for one authenticated WebSocket session. */
export interface RelayWebSocketSessionOptions {
    readonly relay: RelayService;
    readonly claims: RelaySessionClaims;
    readonly peer: RelayWebSocketPeer;
    readonly maximumMessageBytes?: number;
}

/** Token verification policy for WebSocket ingress. */
export interface RelayWebSocketAuthenticationOptions {
    readonly tokenSecret: Uint8Array;
    readonly endpoint: string;
    readonly now?: () => number;
    readonly maximumFutureSkewMilliseconds?: number;
    readonly maximumMessageBytes?: number;
}
