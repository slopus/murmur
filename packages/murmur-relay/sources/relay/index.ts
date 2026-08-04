import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import {
    RelayError,
    isEventId,
    readProofSigningBytes,
    relayEventFingerprint,
    relayTopicId,
    validateRelayTopic,
    validateSignedRelayEventShape,
    verifyRelayEventSignature,
    type ReadChallenge,
    type ReadProof,
    type RelayTopic,
    type SignedRelayEvent,
} from "../protocol/index.js";
import type {
    EventPage,
    PageReadConstraints,
    PublishOutcome,
    RelayStore,
} from "../storage/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";
import { InProcessWakeSource } from "./impl/wakeInProcess.js";
import type { RelayOptions, ResolvedRelayOptions, WakeSource } from "./types.js";

export { InProcessWakeSource } from "./impl/wakeInProcess.js";
export { PostgresWakeSource } from "./impl/wakePostgres.js";
export type { RelayOptions, ResolvedRelayOptions, WakeSource } from "./types.js";

const MEBIBYTE = 1024 * 1024;
const FIVE_MINUTES = 5 * 60 * 1_000;
const HARD_MAXIMUM_LONG_POLL_MILLISECONDS = 30_000;
const MAXIMUM_SEQUENCE = 9_223_372_036_854_775_807n;

interface Waiter {
    readonly resolve: () => void;
    readonly reject: (error: Error) => void;
}

function positiveInteger(value: number, name: string): number {
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new Error(`${name} must be a positive safe integer`);
    }
    return value;
}

function validatedReadProof(value: unknown): ReadProof | undefined {
    if (value === undefined) return undefined;
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, "Invalid read proof", { error: "malformed" });
    }
    const proof = value as Record<string, unknown>;
    if (
        Object.keys(proof).length !== 2 ||
        !Object.hasOwn(proof, "challengeId") ||
        !Object.hasOwn(proof, "signature") ||
        typeof proof.challengeId !== "string" ||
        !(proof.signature instanceof Uint8Array) ||
        proof.signature.length !== 64
    ) {
        throw new RelayError(400, "Invalid read proof", { error: "malformed" });
    }
    return {
        challengeId: proof.challengeId,
        signature: proof.signature,
    };
}

function resolveOptions(options: RelayOptions): ResolvedRelayOptions {
    const resolved = {
        maximumEventPayloadBytes: positiveInteger(
            options.maximumEventPayloadBytes ?? MEBIBYTE,
            "Maximum event payload bytes",
        ),
        maximumCollapseKeyBytes: positiveInteger(
            options.maximumCollapseKeyBytes ?? 256,
            "Maximum collapse key bytes",
        ),
        maximumJsonBodyBytes: positiveInteger(
            options.maximumJsonBodyBytes ?? 2 * MEBIBYTE,
            "Maximum JSON body bytes",
        ),
        maximumEventsPerRead: positiveInteger(
            options.maximumEventsPerRead ?? 256,
            "Maximum events per read",
        ),
        maximumLongPollMilliseconds: positiveInteger(
            options.maximumLongPollMilliseconds ?? 30_000,
            "Maximum long poll milliseconds",
        ),
        maximumConcurrentLongPolls: positiveInteger(
            options.maximumConcurrentLongPolls ?? 10_000,
            "Maximum concurrent long polls",
        ),
        readChallengeLifetimeMilliseconds: positiveInteger(
            options.readChallengeLifetimeMilliseconds ?? 30_000,
            "Read challenge lifetime",
        ),
        maximumOutstandingReadChallenges: positiveInteger(
            options.maximumOutstandingReadChallenges ?? 50_000,
            "Maximum outstanding read challenges",
        ),
    };
    if (resolved.maximumLongPollMilliseconds > HARD_MAXIMUM_LONG_POLL_MILLISECONDS) {
        throw new Error("Maximum long poll cannot exceed 30 seconds");
    }
    const minimumJsonBytes =
        Math.ceil(resolved.maximumEventPayloadBytes / 3) * 4 +
        Math.ceil(resolved.maximumCollapseKeyBytes / 3) * 4 +
        4_096;
    if (resolved.maximumJsonBodyBytes < minimumJsonBytes) {
        throw new Error("Maximum JSON body bytes must fit one maximum-sized encoded relay event");
    }
    return resolved;
}

/** Authorization and long-poll orchestration over one ordered event store. */
export class RelayService {
    readonly #store: RelayStore;
    readonly #wakeSource: WakeSource;
    readonly #now: () => number;
    readonly #options: ResolvedRelayOptions;
    readonly #waiters = new Map<string, Set<Waiter>>();
    #waiterCount = 0;
    #closed = false;

    constructor(
        store: RelayStore,
        options: RelayOptions = {},
        wakeSource: WakeSource = new InProcessWakeSource(),
        now: () => number = Date.now,
    ) {
        this.#store = store;
        this.#options = resolveOptions(options);
        this.#wakeSource = wakeSource;
        this.#now = now;
        void wakeSource.subscribe((topicId) => this.#wake(topicId)).catch(() => undefined);
    }

    /** Resolved immutable limits used by the HTTP boundary. */
    get options(): ResolvedRelayOptions {
        return this.#options;
    }

    /** Validate authorization and atomically append one durable signed event. */
    async publish(event: SignedRelayEvent): Promise<PublishOutcome> {
        this.#assertOpen();
        validateSignedRelayEventShape(event);
        if (
            event.version !== 1 ||
            !isEventId(event.id) ||
            !(event.payload instanceof Uint8Array) ||
            !(event.signature instanceof Uint8Array) ||
            !(event.author.signingKey instanceof Uint8Array) ||
            event.author.signingKey.length !== 32 ||
            event.signature.length !== 64 ||
            !Number.isSafeInteger(event.createdAt) ||
            event.createdAt < 0 ||
            (event.expiresAt !== undefined &&
                (!Number.isSafeInteger(event.expiresAt) || event.expiresAt < 0))
        ) {
            throw new RelayError(400, "Invalid relay event", { error: "malformed" });
        }
        if (event.payload.length > this.#options.maximumEventPayloadBytes) {
            throw new RelayError(413, "Event payload exceeds relay limit", { error: "limit" });
        }
        if (
            event.collapseKey !== undefined &&
            (!(event.collapseKey instanceof Uint8Array) ||
                event.collapseKey.length < 1 ||
                event.collapseKey.length > this.#options.maximumCollapseKeyBytes)
        ) {
            throw new RelayError(400, "Invalid collapse key", { error: "malformed" });
        }
        if (!verifyRelayEventSignature(event)) {
            throw new RelayError(401, "Invalid relay event signature", {
                error: "unauthorized",
            });
        }
        const requiredWriteKey = event.topic.type === "read" ? undefined : event.topic.writeKey;
        if (
            requiredWriteKey !== undefined &&
            !equalBytes(requiredWriteKey, event.author.signingKey)
        ) {
            throw new RelayError(403, "Writer is not authorized for this topic", {
                error: "unauthorized",
            });
        }
        const topicId = relayTopicId(event.topic);
        const receipt = await this.#store.readPublishReceipt(topicId, event.id);
        if (receipt !== undefined) {
            if (!equalBytes(receipt.fingerprint, relayEventFingerprint(event))) {
                throw new RelayError(409, "Event identifier collision", {
                    error: "id_collision",
                });
            }
            return { seq: receipt.seq, duplicate: true };
        }
        const now = this.#now();
        if (
            event.createdAt < now - FIVE_MINUTES ||
            event.createdAt > now + FIVE_MINUTES ||
            (event.expiresAt !== undefined && event.expiresAt <= now)
        ) {
            throw new RelayError(401, "Expired relay event", { error: "unauthorized" });
        }
        const outcome = await this.#store.publish(event, topicId, now);
        if (!outcome.duplicate) {
            this.#wake(topicId);
            await this.#wakeSource.notify(topicId).catch(() => undefined);
        }
        return outcome;
    }

    /** Issue a short-lived one-use challenge for a protected read topic. */
    async issueReadChallenge(topic: RelayTopic): Promise<ReadChallenge> {
        this.#assertOpen();
        validateRelayTopic(topic);
        if (topic.type === "write") {
            throw new RelayError(400, "Publicly readable topics need no challenge", {
                error: "malformed",
            });
        }
        const now = this.#now();
        const challenge: ReadChallenge = {
            id: encodeBase64Url(randomBytes(32)),
            nonce: randomBytes(32),
            expiresAt: now + this.#options.readChallengeLifetimeMilliseconds,
        };
        if (
            !(await this.#store.issueReadChallenge(
                {
                    ...challenge,
                    topicId: relayTopicId(topic),
                },
                now,
                this.#options.maximumOutstandingReadChallenges,
            ))
        ) {
            throw new RelayError(503, "Too many outstanding read challenges", {
                error: "overloaded",
            });
        }
        return challenge;
    }

    /** Read retained events, consuming a signed proof when the topic is protected. */
    async readEvents(
        topic: RelayTopic,
        since: bigint,
        limit: number = this.#options.maximumEventsPerRead,
        waitMilliseconds: number = 0,
        proof?: ReadProof,
        signal?: AbortSignal,
        maximumEncodedBytes: number = Number.MAX_SAFE_INTEGER,
    ): Promise<EventPage> {
        this.#assertOpen();
        validateRelayTopic(topic);
        if (
            typeof since !== "bigint" ||
            since < 0n ||
            since > MAXIMUM_SEQUENCE ||
            !Number.isSafeInteger(limit) ||
            limit < 1 ||
            limit > this.#options.maximumEventsPerRead ||
            !Number.isSafeInteger(waitMilliseconds) ||
            waitMilliseconds < 0 ||
            waitMilliseconds > this.#options.maximumLongPollMilliseconds ||
            !Number.isSafeInteger(maximumEncodedBytes) ||
            maximumEncodedBytes < 1
        ) {
            throw new RelayError(400, "Invalid event read", { error: "malformed" });
        }
        const checkedProof = validatedReadProof(proof);
        await this.#authorizeRead(topic, since, limit, waitMilliseconds, checkedProof);
        const topicId = relayTopicId(topic);
        const constraints: PageReadConstraints = { maximumEncodedBytes };
        const current = await this.#store.readEvents(
            topicId,
            since,
            limit,
            this.#now(),
            constraints,
        );
        if (since > current.head) {
            throw new RelayError(400, "Event cursor is beyond the topic head", {
                error: "malformed",
            });
        }
        if (current.events.length > 0 || current.head > since || waitMilliseconds === 0) {
            return current;
        }
        await this.#park(
            topicId,
            waitMilliseconds,
            async () => {
                const page = await this.#store.readEvents(
                    topicId,
                    since,
                    limit,
                    this.#now(),
                    constraints,
                );
                return page.events.length > 0 || page.head > since;
            },
            signal,
        );
        const result = await this.#store.readEvents(
            topicId,
            since,
            limit,
            this.#now(),
            constraints,
        );
        if (since > result.head) {
            throw new RelayError(400, "Event cursor is beyond the topic head", {
                error: "malformed",
            });
        }
        return result;
    }

    /** Delete only events whose explicit expiration has elapsed. */
    async pruneExpired(): Promise<number> {
        this.#assertOpen();
        return this.#store.pruneExpired(this.#now());
    }

    /** Confirm the backing store is reachable. */
    async health(): Promise<void> {
        this.#assertOpen();
        await this.#store.health();
    }

    /** Stop waiters and close dependencies. */
    async close(): Promise<void> {
        if (this.#closed) return;
        this.#closed = true;
        for (const waiters of this.#waiters.values()) {
            for (const waiter of waiters) waiter.reject(new Error("Relay service closed"));
        }
        try {
            await this.#wakeSource.close();
        } finally {
            await this.#store.close();
        }
    }

    async #authorizeRead(
        topic: RelayTopic,
        since: bigint,
        limit: number,
        waitMilliseconds: number,
        proof: ReadProof | undefined,
    ): Promise<void> {
        if (topic.type === "write") {
            if (proof !== undefined) {
                throw new RelayError(400, "Public read must not include a proof", {
                    error: "malformed",
                });
            }
            return;
        }
        if (proof === undefined || proof.signature.length !== 64) {
            throw new RelayError(401, "Read proof required", { error: "unauthorized" });
        }
        const stored = await this.#store.consumeReadChallenge(proof.challengeId, this.#now());
        if (stored === undefined || stored.topicId !== relayTopicId(topic)) {
            throw new RelayError(401, "Invalid or expired read challenge", {
                error: "unauthorized",
            });
        }
        try {
            if (
                !ed25519.verify(
                    proof.signature,
                    readProofSigningBytes(
                        {
                            id: stored.id,
                            nonce: stored.nonce,
                            expiresAt: stored.expiresAt,
                        },
                        topic,
                        since,
                        limit,
                        waitMilliseconds,
                    ),
                    topic.readKey,
                    { zip215: false },
                )
            ) {
                throw new Error("invalid");
            }
        } catch {
            throw new RelayError(401, "Invalid read proof", { error: "unauthorized" });
        }
    }

    async #park(
        topicId: string,
        milliseconds: number,
        recheck: () => Promise<boolean>,
        signal?: AbortSignal,
    ): Promise<void> {
        if (signal?.aborted === true) throw new Error("Long poll aborted");
        if (this.#waiterCount >= this.#options.maximumConcurrentLongPolls) {
            throw new RelayError(503, "Too many concurrent long polls", { error: "overloaded" });
        }
        await new Promise<void>((resolve, reject) => {
            const waiters = this.#waiters.get(topicId) ?? new Set<Waiter>();
            let done = false;
            let timer: ReturnType<typeof setTimeout>;
            const finish = (error?: Error): void => {
                if (done) return;
                done = true;
                clearTimeout(timer);
                signal?.removeEventListener("abort", abort);
                waiters.delete(waiter);
                this.#waiterCount -= 1;
                if (waiters.size === 0) this.#waiters.delete(topicId);
                if (error === undefined) {
                    resolve();
                } else {
                    reject(error);
                }
            };
            const abort = (): void => finish(new Error("Long poll aborted"));
            const waiter: Waiter = { resolve: () => finish(), reject: finish };
            waiters.add(waiter);
            this.#waiterCount += 1;
            this.#waiters.set(topicId, waiters);
            timer = setTimeout(() => finish(), milliseconds);
            signal?.addEventListener("abort", abort, { once: true });
            if (signal?.aborted === true) {
                abort();
            }
            void recheck().then(
                (ready) => {
                    if (ready) waiter.resolve();
                },
                (error: unknown) => {
                    waiter.reject(
                        error instanceof Error ? error : new Error("Relay recheck failed"),
                    );
                },
            );
        });
    }

    #wake(topicId: string): void {
        for (const waiter of this.#waiters.get(topicId) ?? []) waiter.resolve();
    }

    #assertOpen(): void {
        if (this.#closed) throw new Error("Relay service is closed");
    }
}
