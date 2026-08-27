import { Client, type ClientConfig, type Notification } from "pg";
import { POSTGRES_WAKE_CHANNEL } from "../../storage/postgres/index.js";
import type { WakeSource } from "../types.js";

const RECONNECT_MILLISECONDS = 1_000;
const DEVICE_ROSTER_WAKE_PREFIX = "device-roster:";

/** Dedicated resilient Postgres LISTEN connection for cross-instance queue wakes. */
export class PostgresWakeSource implements WakeSource {
    readonly #configuration: ClientConfig;
    readonly #listeners = new Set<(queueId: string) => void>();
    #client: Client | undefined;
    #reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    #connecting = false;
    #closed = false;

    constructor(configuration: ClientConfig) {
        this.#configuration = configuration;
    }

    /**
     * Publication notifications are emitted by PostgresRelayStore inside its
     * transaction; this method is intentionally a no-op after local commit.
     */
    async notify(queueId: string): Promise<void> {
        if (!queueId.startsWith(DEVICE_ROSTER_WAKE_PREFIX)) return;
        const client = this.#client;
        if (client === undefined) throw new Error("Postgres wake source is unavailable");
        await client.query("SELECT pg_notify($1, $2)", [POSTGRES_WAKE_CHANNEL, queueId]);
    }

    /** Register a listener and establish the dedicated LISTEN connection. */
    async subscribe(listener: (queueId: string) => void): Promise<void> {
        if (this.#closed) {
            throw new Error("Wake source is closed");
        }
        this.#listeners.add(listener);
        try {
            await this.#connect(true);
        } catch (error) {
            this.#listeners.delete(listener);
            throw error;
        }
    }

    /** End LISTEN and cancel reconnect attempts without affecting the main pool. */
    async close(): Promise<void> {
        this.#closed = true;
        if (this.#reconnectTimer !== undefined) {
            clearTimeout(this.#reconnectTimer);
            this.#reconnectTimer = undefined;
        }
        const client = this.#client;
        this.#client = undefined;
        if (client !== undefined) {
            await client.end().catch(() => undefined);
        }
        this.#listeners.clear();
    }

    async #connect(required: boolean = false): Promise<void> {
        if (this.#closed || this.#connecting || this.#client !== undefined) {
            return;
        }
        this.#connecting = true;
        const client = new Client(this.#configuration);
        this.#client = client;
        client.on("error", () => {
            this.#disconnect(client);
        });
        client.on("end", () => {
            this.#disconnect(client);
        });
        client.on("notification", (notification: Notification) => {
            if (
                notification.channel === POSTGRES_WAKE_CHANNEL &&
                notification.payload !== undefined
            ) {
                for (const listener of this.#listeners) {
                    listener(notification.payload);
                }
            }
        });
        try {
            await client.connect();
            await client.query(`LISTEN ${POSTGRES_WAKE_CHANNEL}`);
            if (this.#closed) {
                if (this.#client === client) {
                    this.#client = undefined;
                }
                await client.end().catch(() => undefined);
            }
        } catch (error) {
            if (this.#client === client) {
                this.#client = undefined;
            }
            await client.end().catch(() => undefined);
            if (required) {
                if (this.#reconnectTimer !== undefined) {
                    clearTimeout(this.#reconnectTimer);
                    this.#reconnectTimer = undefined;
                }
                throw error;
            }
            this.#scheduleReconnect();
        } finally {
            this.#connecting = false;
        }
    }

    #disconnect(client: Client): void {
        if (this.#client === client) {
            this.#client = undefined;
        }
        this.#scheduleReconnect();
    }

    #scheduleReconnect(): void {
        if (this.#closed || this.#reconnectTimer !== undefined) {
            return;
        }
        this.#reconnectTimer = setTimeout(() => {
            this.#reconnectTimer = undefined;
            void this.#connect();
        }, RECONNECT_MILLISECONDS);
        this.#reconnectTimer.unref();
    }
}
