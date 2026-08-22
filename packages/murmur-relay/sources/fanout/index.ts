import type { SignedDelivery } from "../protocol/index.js";
import type { PublishOutcome } from "../storage/index.js";
import type {
    DurableFanoutCoordinatorOptions,
    DurableFanoutStore,
    FanoutRetryOutcome,
    FanoutRetryScheduler,
    FanoutTarget,
} from "./types.js";

export type {
    DurableFanoutCoordinatorOptions,
    DurableFanoutStore,
    FanoutRetryOutcome,
    FanoutRetryScheduler,
    FanoutTarget,
    PendingFanoutManifest,
} from "./types.js";

const DEFAULT_RETRY_DELAY_MILLISECONDS = 1_000;
const DEFAULT_MAXIMUM_MANIFESTS_PER_RUN = 32;

/** Persist-first, ordered, idempotent fanout without cross-target transactions. */
export class DurableFanoutCoordinator {
    readonly #store: DurableFanoutStore;
    readonly #target: FanoutTarget;
    readonly #scheduler: FanoutRetryScheduler;
    readonly #now: () => number;
    readonly #retryDelayMilliseconds: number;
    readonly #maximumManifestsPerRun: number;
    #retrying: Promise<FanoutRetryOutcome> | undefined;

    constructor(
        store: DurableFanoutStore,
        target: FanoutTarget,
        scheduler: FanoutRetryScheduler,
        options: DurableFanoutCoordinatorOptions = {},
    ) {
        this.#store = store;
        this.#target = target;
        this.#scheduler = scheduler;
        this.#now = options.now ?? Date.now;
        this.#retryDelayMilliseconds =
            options.retryDelayMilliseconds ?? DEFAULT_RETRY_DELAY_MILLISECONDS;
        this.#maximumManifestsPerRun =
            options.maximumManifestsPerRun ?? DEFAULT_MAXIMUM_MANIFESTS_PER_RUN;
        if (
            !Number.isSafeInteger(this.#retryDelayMilliseconds) ||
            this.#retryDelayMilliseconds < 1 ||
            this.#retryDelayMilliseconds > 5 * 60 * 1_000
        ) {
            throw new Error("Fanout retry delay must be between 1ms and 5 minutes");
        }
        if (
            !Number.isSafeInteger(this.#maximumManifestsPerRun) ||
            this.#maximumManifestsPerRun < 1 ||
            this.#maximumManifestsPerRun > 1_024
        ) {
            throw new Error("Fanout run bound must contain 1 through 1024 manifests");
        }
    }

    /** Durably reserve the event and complete target set before reporting acceptance. */
    async publish(delivery: SignedDelivery, admissionPrincipal: string): Promise<PublishOutcome> {
        const now = this.#now();
        const outcome = await this.#store.reserve(delivery, admissionPrincipal, now);
        await this.#scheduler.schedule(now);
        return outcome;
    }

    /** Retry oldest-first; later events never overtake an incomplete manifest. */
    retry(): Promise<FanoutRetryOutcome> {
        this.#retrying ??= this.#run().finally(() => {
            this.#retrying = undefined;
        });
        return this.#retrying;
    }

    async #run(): Promise<FanoutRetryOutcome> {
        let completedManifests = 0;
        await this.#store.pruneExpired(this.#now());
        while (completedManifests < this.#maximumManifestsPerRun) {
            const manifest = await this.#store.oldestPending(this.#now());
            if (manifest === undefined) {
                return { completedManifests, pending: false };
            }
            let failed = false;
            await Promise.all(
                manifest.pendingRecipients.map(async (recipient) => {
                    try {
                        await this.#target.insert(
                            recipient,
                            manifest.eventId,
                            manifest.delivery,
                            manifest.admissionPrincipal,
                        );
                        await this.#store.markDelivered(
                            manifest.delivery.sender,
                            manifest.delivery.id,
                            recipient,
                        );
                    } catch {
                        failed = true;
                    }
                }),
            );
            if (failed) {
                await this.#scheduler.schedule(this.#now() + this.#retryDelayMilliseconds);
                return { completedManifests, pending: true };
            }
            completedManifests += 1;
        }
        const pending = (await this.#store.oldestPending(this.#now())) !== undefined;
        if (pending) await this.#scheduler.schedule(this.#now());
        return { completedManifests, pending };
    }
}
