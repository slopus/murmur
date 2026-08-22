/** Minimal Durable Object identifier surface used by the Worker adapter. */
export interface DurableObjectIdLike {
    toString(): string;
}

/** Minimal Durable Object stub surface used for internal requests. */
export interface DurableObjectStubLike {
    fetch(request: Request): Promise<Response>;
}

/** Minimal Durable Object namespace surface used by this deployment. */
export interface DurableObjectNamespaceLike {
    idFromName(name: string): DurableObjectIdLike;
    get(id: DurableObjectIdLike): DurableObjectStubLike;
}

/** Options accepted by Durable Object storage list operations. */
export interface DurableObjectListOptions {
    readonly prefix?: string;
    readonly startAfter?: string;
    readonly end?: string;
    readonly limit?: number;
}

/** Minimal Durable Object storage transaction. */
export interface DurableObjectTransactionLike {
    get<T>(key: string): Promise<T | undefined>;
    put<T>(key: string, value: T): Promise<void>;
    delete(key: string | readonly string[]): Promise<boolean | number>;
    list<T>(options?: DurableObjectListOptions): Promise<Map<string, T>>;
}

/** Minimal Durable Object storage surface used by both object classes. */
export interface DurableObjectStorageLike extends DurableObjectTransactionLike {
    transaction<T>(closure: (transaction: DurableObjectTransactionLike) => Promise<T>): Promise<T>;
    getAlarm(): Promise<number | null>;
    setAlarm(scheduledTime: number): Promise<void>;
}

/** Attachment retained with a hibernated WebSocket. */
export interface CloudflareWebSocketAttachment {
    readonly device: string;
    readonly admissionPrincipal: string;
    readonly expiresAt: number;
    readonly started?: boolean;
    readonly streamId?: string;
    readonly after?: string | null;
}

/** Minimal Cloudflare server WebSocket surface. */
export interface CloudflareServerWebSocket {
    send(message: string): void;
    close(code?: number, reason?: string): void;
    serializeAttachment(value: CloudflareWebSocketAttachment): void;
    deserializeAttachment(): CloudflareWebSocketAttachment | null;
}

/** Minimal Durable Object state surface used by hibernating WebSockets. */
export interface DurableObjectStateLike {
    readonly storage: DurableObjectStorageLike;
    acceptWebSocket(socket: CloudflareServerWebSocket, tags?: readonly string[]): void;
    getWebSockets(tag?: string): readonly CloudflareServerWebSocket[];
    waitUntil(promise: Promise<unknown>): void;
}

/** Bindings required by the Cloudflare Worker and both Durable Objects. */
export interface MurmurCloudflareEnvironment {
    readonly MURMUR_INBOXES: DurableObjectNamespaceLike;
    readonly MURMUR_FANOUT: DurableObjectNamespaceLike;
    /** Canonical unpadded base64url HMAC secret containing at least 32 bytes. */
    readonly MURMUR_RELAY_TOKEN_SECRET: string;
    /** Exact public `wss:` URL returned by the application's ticket issuer. */
    readonly MURMUR_RELAY_ENDPOINT: string;
}
