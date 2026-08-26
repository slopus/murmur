import { sha256 } from "@noble/hashes/sha2";
import {
    parseSignedDelivery,
    signedDeliveryToJson,
    type SignedDelivery,
    type SignedDeliveryJson,
} from "../../protocol/index.js";
import { decodeBase64Url, encodeBase64Url } from "../../utils/base64Url.js";
import type { CloudflareServerWebSocket } from "../types.js";

export const MAXIMUM_MESSAGE_BYTES = 16 * 1024 * 1024;
export const MAXIMUM_AUTHENTICATION_SKEW_MILLISECONDS = 5 * 60 * 1_000;
export const MAXIMUM_DELIVERY_TTL_MILLISECONDS = 180 * 24 * 60 * 60 * 1_000;
export const MAXIMUM_CIPHERTEXT_BYTES = 1024 * 1024;
export const MAXIMUM_RECIPIENTS = 256;
export const MAXIMUM_QUEUE_ITEMS = 10_000;
export const MAXIMUM_QUEUE_BYTES = 256 * 1024 * 1024;
export const STREAM_HEARTBEAT_MILLISECONDS = 15_000;
export const textEncoder = new TextEncoder();

export interface CloudflareRequestFrame {
    readonly id: string;
    readonly operation:
        | "publish"
        | "delete_session"
        | "delete_account"
        | "read_device_roster"
        | "mutate_device_roster"
        | "upload_directory_prekeys"
        | "claim_directory"
        | "read"
        | "acknowledge"
        | "stream";
    readonly body: unknown;
}

export interface StoredDeliveryRecord {
    readonly eventId: string;
    readonly sequence: number;
    readonly delivery: SignedDeliveryJson;
    readonly encodedBytes: number;
    readonly senderCounter: string;
    readonly principalCounter: string;
    readonly expiryKey: string;
}

export interface InboxMetadata {
    readonly head: string | null;
    readonly headSequence: number;
    readonly nextSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: string;
    readonly pendingItems: number;
    readonly pendingBytes: number;
}

export function object(value: unknown): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Invalid value");
    }
    return value as Record<string, unknown>;
}

export function exact(value: Record<string, unknown>, fields: readonly string[]): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid value");
    }
}

export function requestFrame(message: string): CloudflareRequestFrame {
    if (textEncoder.encode(message).length > MAXIMUM_MESSAGE_BYTES) {
        throw new Error("Message exceeds limit");
    }
    const input = object(JSON.parse(message) as unknown);
    exact(input, ["version", "id", "operation", "body"]);
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        !/^[A-Za-z0-9_-]{24}$/.test(input.id) ||
        (input.operation !== "publish" &&
            input.operation !== "delete_session" &&
            input.operation !== "delete_account" &&
            input.operation !== "read_device_roster" &&
            input.operation !== "mutate_device_roster" &&
            input.operation !== "upload_directory_prekeys" &&
            input.operation !== "claim_directory" &&
            input.operation !== "read" &&
            input.operation !== "acknowledge" &&
            input.operation !== "stream")
    ) {
        throw new Error("Invalid request frame");
    }
    return { id: input.id, operation: input.operation, body: input.body };
}

export function responseFrame(id: string, status: number, body: unknown): string {
    return JSON.stringify({ version: 1, id, type: "response", status, body });
}

export function deliveryFrame(
    id: string,
    eventId: string,
    sequence: number,
    delivery: SignedDeliveryJson,
): string {
    return JSON.stringify({
        version: 1,
        id,
        type: "delivery",
        body: { eventId, sequence, delivery },
    });
}

export function continuityFrame(id: string, metadata: InboxMetadata): string {
    return JSON.stringify({
        version: 1,
        id,
        type: "continuity",
        body: {
            generation: metadata.generation,
            head: metadata.head,
            headSequence: metadata.headSequence,
            acknowledgedThrough: metadata.acknowledgedThrough,
            acknowledgedSequence: metadata.acknowledgedSequence,
        },
    });
}

export function heartbeatFrame(id: string): string {
    return JSON.stringify({ version: 1, id, type: "heartbeat", body: null });
}

export function send(socket: CloudflareServerWebSocket, message: string): void {
    if (textEncoder.encode(message).length > MAXIMUM_MESSAGE_BYTES) {
        throw new Error("WebSocket response exceeds limit");
    }
    socket.send(message);
}

export function parseTokenSecret(value: string): Uint8Array {
    const secret = decodeBase64Url(value);
    if (secret.length < 32 || encodeBase64Url(secret) !== value) {
        throw new Error("MURMUR_RELAY_TOKEN_SECRET must be canonical base64url");
    }
    return secret;
}

/** Derive a domain-separated Ed25519 directory-ticket seed from the relay secret. */
export function deriveCloudflareDirectoryTicketSecret(value: string): Uint8Array {
    const hash = sha256.create();
    hash.update(textEncoder.encode("murmur.cloudflare.directory-ticket.v1\0"));
    hash.update(parseTokenSecret(value));
    return hash.digest();
}

export function encodedDeliveryBytes(delivery: SignedDelivery): number {
    return textEncoder.encode(JSON.stringify(signedDeliveryToJson(delivery))).length;
}

export function decodeStoredDelivery(value: SignedDeliveryJson): SignedDelivery {
    return parseSignedDelivery(value);
}

export function websocketPair(): {
    readonly client: CloudflareServerWebSocket;
    readonly server: CloudflareServerWebSocket;
} {
    const constructor = (
        globalThis as unknown as {
            readonly WebSocketPair: new () => {
                readonly 0: CloudflareServerWebSocket;
                readonly 1: CloudflareServerWebSocket;
            };
        }
    ).WebSocketPair;
    const pair = new constructor();
    return { client: pair[0], server: pair[1] };
}

export function websocketResponse(client: CloudflareServerWebSocket): Response {
    return new Response(null, {
        status: 101,
        headers: { "sec-websocket-protocol": "murmur-websocket-v1" },
        webSocket: client,
    } as unknown as ResponseInit);
}
