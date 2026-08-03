import {
    MemoryMurmurStore,
    MurmurClient,
    createRelayBlob,
    equalRelayEvents,
    generateIdentityKeyPair,
    verifyRelayBlob,
    type EventPage,
    type ListPage,
    type PublishOutcome,
    type RelayBlob,
    type RelayTransport,
    type SignedRelayEvent,
    type TopicState,
} from "@slopus/murmur";
import type {
    SessionEntrySource,
    SharedSessionCallbacks,
    SharedSessionControl,
    SharedSessionEntry,
    SharedSessionEphemeralTransport,
    SharedSessionPost,
    SharedSessionState,
    SharedSessionTopicStream,
} from "../index.js";
import type { SharedSessionMember, SharedSessionOwner } from "../index.js";

/** In-memory durable relay used by every shared-session test. */
export class MemoryRelayTransport implements RelayTransport {
    readonly id = "memory";
    readonly #events = new Map<string, SignedRelayEvent[]>();
    readonly #blobs = new Map<string, Uint8Array>();

    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        const events = this.#events.get(event.topic) ?? [];
        const prior = events.find((candidate) => candidate.id === event.id);
        if (prior !== undefined) {
            if (!equalRelayEvents(prior, event)) {
                throw new Error("event collision");
            }
            return { seq: BigInt(events.indexOf(prior) + 1), duplicate: true };
        }
        events.push(event);
        this.#events.set(event.topic, events);
        return { seq: BigInt(events.length), duplicate: false };
    }

    async readState(topic: string): Promise<TopicState | undefined> {
        const events = this.#events.get(topic) ?? [];
        return {
            seq: BigInt(events.length),
            snapshot: null,
            list: { elements: [], nextCursor: null },
        };
    }

    async readList(): Promise<ListPage | undefined> {
        return { elements: [], nextCursor: null };
    }

    async readEvents(topic: string, since: bigint, limit: number = 100): Promise<EventPage> {
        const events = this.#events.get(topic) ?? [];
        const start = Number(since);
        return {
            events: events.slice(start, start + limit).map((event, index) => ({
                seq: BigInt(start + index + 1),
                event,
            })),
            reset: false,
            seq: BigInt(events.length),
        };
    }

    async putBlob(blob: RelayBlob): Promise<void> {
        if (!verifyRelayBlob(blob)) {
            throw new Error("invalid blob");
        }
        this.#blobs.set(blob.id, blob.bytes.slice());
    }

    async getBlob(id: string, expectedBytes?: number): Promise<RelayBlob | undefined> {
        const bytes = this.#blobs.get(id);
        if (bytes === undefined) {
            return undefined;
        }
        if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
            throw new Error("blob size mismatch");
        }
        return createRelayBlob(bytes);
    }

    events(topic: string): readonly SignedRelayEvent[] {
        return [...(this.#events.get(topic) ?? [])];
    }
}

/** Everything the application callbacks recorded. */
export interface Captured {
    readonly entries: SharedSessionEntry[];
    readonly states: SharedSessionState[];
    readonly posts: SharedSessionPost[];
    readonly controls: SharedSessionControl[];
    readonly terminations: string[];
}

export function captured(): Captured {
    return { entries: [], states: [], posts: [], controls: [], terminations: [] };
}

/** Application hooks; `withControl` decides whether friend control is accepted. */
export function callbacks(recorded: Captured, withControl: boolean = true): SharedSessionCallbacks {
    return {
        persistEntry: async (_transaction, entry) => {
            recorded.entries.push(entry);
        },
        persistState: async (_transaction, state) => {
            recorded.states.push(state);
        },
        persistPost: async (_transaction, post) => {
            recorded.posts.push(post);
        },
        ...(withControl
            ? {
                  persistControl: async (
                      _transaction: unknown,
                      control: SharedSessionControl,
                  ): Promise<void> => {
                      recorded.controls.push(control);
                  },
              }
            : {}),
        terminate: async (_transaction, termination) => {
            recorded.terminations.push(termination.reason);
        },
    };
}

export function emptySource(): SessionEntrySource {
    return { readPage: async () => ({ entries: [], done: true }) };
}

export function client(
    identity: ReturnType<typeof generateIdentityKeyPair>,
    store: MemoryMurmurStore,
    relay: RelayTransport,
): MurmurClient {
    return new MurmurClient({ identity, store, transports: [relay] });
}

export async function drain(
    murmur: MurmurClient,
    session: Pick<SharedSessionMember | SharedSessionOwner, "handleEvent">,
): Promise<void> {
    const sync = await murmur.sync();
    if (sync.status !== "events") {
        throw new Error("unexpected reset");
    }
    for (const event of sync.events) {
        await session.handleEvent(event);
    }
}

/** One process's view of the relay's in-process ephemeral fan-out. */
export class LoopbackEphemeralRelay {
    readonly #subscribers = new Map<string, Set<(bytes: Uint8Array) => void>>();
    /** Frames published while held, released in order by `release()`. */
    readonly #held: (() => void)[] = [];
    #holding = false;
    published = 0;

    hold(): void {
        this.#holding = true;
    }

    release(): void {
        this.#holding = false;
        for (const resume of this.#held.splice(0)) {
            resume();
        }
    }

    /** Detach every current stream, as a relay restart or network drop would. */
    disconnect(): void {
        this.#subscribers.clear();
    }

    subscribers(topic: string): number {
        return this.#subscribers.get(topic)?.size ?? 0;
    }

    /**
     * Deliver arbitrary bytes to every subscriber of a topic.
     *
     * The relay's ephemeral publish is unauthenticated by design, so anyone who
     * learns a topic can do exactly this.
     */
    inject(topic: string, bytes: Uint8Array): void {
        // Snapshot first: a listener may close its stream while notified.
        const listeners = [...(this.#subscribers.get(topic) ?? [])];
        for (const listener of listeners) {
            listener(bytes.slice());
        }
    }

    transportFor(): SharedSessionEphemeralTransport {
        return {
            publishEphemeral: async (topic, frame): Promise<number> => {
                if (this.#holding) {
                    await new Promise<void>((resolve) => {
                        this.#held.push(resolve);
                    });
                }
                const listeners = this.#subscribers.get(topic);
                this.published += 1;
                const snapshot = [...(listeners ?? [])];
                for (const listener of snapshot) {
                    listener(frame.slice());
                }
                return listeners?.size ?? 0;
            },
            openTopicStream: (topic, handlers): SharedSessionTopicStream => {
                const listener = (bytes: Uint8Array): void => {
                    handlers.onFrame?.({ relayId: "loopback", bytes });
                };
                const listeners = this.#subscribers.get(topic) ?? new Set();
                listeners.add(listener);
                this.#subscribers.set(topic, listeners);
                let connected = true;
                return {
                    get connected(): boolean {
                        return connected;
                    },
                    close: (): void => {
                        connected = false;
                        this.#subscribers.get(topic)?.delete(listener);
                    },
                };
            },
        };
    }
}
