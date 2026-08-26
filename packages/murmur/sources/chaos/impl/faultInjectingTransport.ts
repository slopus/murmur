import type {
    DeliveryPublishOutcome,
    DeliveryDeviceRoster,
    DeliveryStreamHooks,
    DeliveryTransport,
    InboxDelivery,
    InboxStreamEvent,
    InboxPage,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../../delivery/index.js";
import type {
    ChaosAtomicEffect,
    ChaosDelayHandler,
    ChaosPoint,
    ChaosSchedule,
    FaultInjectingTransportOptions,
} from "../types.js";
import { ChaosCrashError, ChaosInjectedError, chaosEffects } from "./seededSchedule.js";

interface TransportFaultContext {
    readonly actor: string;
    readonly delegate: DeliveryTransport;
    readonly schedule: ChaosSchedule;
    readonly delay: ChaosDelayHandler;
    readonly classifyDelivery: (delivery: SignedDelivery) => number | undefined;
    readonly counts: Map<string, number>;
}

function cloneDelivery(delivery: SignedDelivery): SignedDelivery {
    return {
        version: 1,
        id: delivery.id,
        sender: delivery.sender.slice(),
        recipients: delivery.recipients.map((recipient) => recipient.slice()),
        targetAccounts: delivery.targetAccounts.map((target) => ({
            accountKey: target.accountKey.slice(),
            rosterRevision: target.rosterRevision,
        })),
        createdAt: delivery.createdAt,
        expiresAt: delivery.expiresAt,
        ciphertext: delivery.ciphertext.slice(),
        signature: delivery.signature.slice(),
    };
}

function cloneInboxDelivery(item: InboxDelivery): InboxDelivery {
    return {
        eventId: item.eventId,
        ...(item.sequence === undefined ? {} : { sequence: item.sequence }),
        delivery: cloneDelivery(item.delivery),
    };
}

function clonePage(page: InboxPage): InboxPage {
    return {
        deliveries: page.deliveries.map(cloneInboxDelivery),
        head: page.head,
        ...(page.headSequence === undefined ? {} : { headSequence: page.headSequence }),
        acknowledgedThrough: page.acknowledgedThrough,
        ...(page.acknowledgedSequence === undefined
            ? {}
            : { acknowledgedSequence: page.acknowledgedSequence }),
        ...(page.generation === undefined ? {} : { generation: page.generation.slice() }),
        exhausted: page.exhausted,
    };
}

function cloneRead(request: SignedInboxRead): SignedInboxRead {
    return {
        version: 1,
        recipient: request.recipient.slice(),
        after: request.after,
        limit: request.limit,
        waitMilliseconds: request.waitMilliseconds,
        createdAt: request.createdAt,
        signature: request.signature.slice(),
    };
}

function cloneAck(request: SignedInboxAck): SignedInboxAck {
    return {
        version: 1,
        recipient: request.recipient.slice(),
        through: request.through,
        createdAt: request.createdAt,
        signature: request.signature.slice(),
    };
}

function nextOrdinal(context: TransportFaultContext, operation: string): number {
    const ordinal = (context.counts.get(operation) ?? 0) + 1;
    context.counts.set(operation, ordinal);
    return ordinal;
}

function point(
    context: TransportFaultContext,
    operation: string,
    phase: "before" | "after",
    ordinal: number,
    delivery?: SignedDelivery,
): ChaosPoint {
    const kind = delivery === undefined ? undefined : context.classifyDelivery(delivery);
    return Object.freeze({
        actor: context.actor,
        boundary: "transport",
        operation,
        phase,
        ordinal,
        ...(delivery === undefined ? {} : { deliveryId: delivery.id }),
        ...(kind === undefined ? {} : { deliveryKind: kind }),
    });
}

async function control(
    effect: ChaosAtomicEffect,
    at: ChaosPoint,
    context: TransportFaultContext,
    signal?: AbortSignal,
): Promise<void> {
    signal?.throwIfAborted();
    if (effect.type === "throw") throw new ChaosInjectedError(at, effect.message);
    if (effect.type === "crash") throw new ChaosCrashError(at, effect.message);
    if (effect.type === "delay") {
        await context.delay(effect.milliseconds, at);
        signal?.throwIfAborted();
    }
}

function unsupported(effect: ChaosAtomicEffect, at: ChaosPoint): never {
    throw new Error(
        `Chaos effect ${effect.type} is unsupported for ${at.boundary}:${at.operation}:${at.phase}`,
    );
}

function corrupt(bytes: Uint8Array, effect: Extract<ChaosAtomicEffect, { type: "corrupt" }>): void {
    if (effect.offset >= bytes.length) {
        throw new Error("Chaos corruption offset exceeds the selected delivery bytes");
    }
    bytes[effect.offset] = bytes[effect.offset]! ^ effect.xor;
}

function duplicateAt<T>(values: readonly T[], copies: number, index?: number): T[] {
    if (values.length < 1) throw new Error("Chaos duplication requires a selected value");
    const selected = index ?? values.length - 1;
    if (selected >= values.length) throw new Error("Chaos duplicate index exceeds response size");
    const result = [...values];
    result.splice(selected + 1, 0, ...Array.from({ length: copies }, () => values[selected]!));
    return result;
}

async function applyRequestEffects(
    context: TransportFaultContext,
    at: ChaosPoint,
    signal: AbortSignal | undefined,
    inputBytes: Uint8Array,
): Promise<{
    readonly bytes: Uint8Array;
    readonly dropped: boolean;
    readonly duplicateCopies: number;
}> {
    let bytes = inputBytes.slice();
    let dropped = false;
    let duplicateCopies = 0;
    for (const effect of chaosEffects(context.schedule.decide(at))) {
        await control(effect, at, context, signal);
        if (effect.type === "drop") {
            dropped = true;
        } else if (effect.type === "duplicate") {
            duplicateCopies += effect.copies;
        } else if (effect.type === "corrupt") {
            corrupt(bytes, effect);
        } else if (effect.type === "truncate") {
            bytes = bytes.slice(0, effect.limit);
        } else if (
            effect.type !== "continue" &&
            effect.type !== "throw" &&
            effect.type !== "crash" &&
            effect.type !== "delay"
        ) {
            unsupported(effect, at);
        }
    }
    return { bytes, dropped, duplicateCopies };
}

async function applyResponseControl(
    context: TransportFaultContext,
    at: ChaosPoint,
    signal?: AbortSignal,
): Promise<number> {
    let duplicateCopies = 0;
    for (const effect of chaosEffects(context.schedule.decide(at))) {
        await control(effect, at, context, signal);
        if (effect.type === "drop") {
            throw new ChaosInjectedError(at, "Injected lost transport response");
        }
        if (effect.type === "duplicate") {
            duplicateCopies += effect.copies;
        } else if (
            effect.type !== "continue" &&
            effect.type !== "throw" &&
            effect.type !== "crash" &&
            effect.type !== "delay"
        ) {
            unsupported(effect, at);
        }
    }
    return duplicateCopies;
}

/** DeliveryTransport wrapper with deterministic request, response, page, and stream faults. */
export class FaultInjectingDeliveryTransport implements DeliveryTransport {
    readonly #context: TransportFaultContext;
    #lastReadPage: InboxPage | undefined;
    #lastStreamDelivery: InboxDelivery | undefined;
    readonly stream?: NonNullable<DeliveryTransport["stream"]>;

    constructor(options: FaultInjectingTransportOptions) {
        if (options.actor.length < 1) throw new Error("Chaos transport actor cannot be empty");
        this.#context = {
            actor: options.actor,
            delegate: options.delegate,
            schedule: options.schedule,
            delay: options.delay ?? (() => undefined),
            classifyDelivery: options.classifyDelivery ?? (() => undefined),
            counts: new Map(),
        };
        if (options.delegate.stream !== undefined) {
            this.stream = (request, signal, hooks) => this.#stream(request, signal, hooks);
        }
    }

    /** Defensive snapshot of per-operation call ordinals. */
    get operationCounts(): ReadonlyMap<string, number> {
        return new Map(this.#context.counts);
    }

    async publish(input: SignedDelivery, signal?: AbortSignal): Promise<DeliveryPublishOutcome> {
        const ordinal = nextOrdinal(this.#context, "publish");
        let delivery = cloneDelivery(input);
        const before = point(this.#context, "publish", "before", ordinal, delivery);
        const request = await applyRequestEffects(
            this.#context,
            before,
            signal,
            delivery.ciphertext,
        );
        delivery = { ...delivery, ciphertext: request.bytes };
        if (request.dropped) {
            throw new ChaosInjectedError(before, "Injected dropped transport request");
        }
        let outcome = await this.#context.delegate.publish(delivery, signal);
        for (let copy = 0; copy < request.duplicateCopies; copy += 1) {
            outcome = await this.#context.delegate.publish(delivery, signal);
        }
        const after = point(this.#context, "publish", "after", ordinal, delivery);
        const duplicates = await applyResponseControl(this.#context, after, signal);
        for (let copy = 0; copy < duplicates; copy += 1) {
            await this.#context.delegate.publish(delivery, signal);
        }
        return { eventId: outcome.eventId, duplicate: outcome.duplicate };
    }

    async read(input: SignedInboxRead, signal?: AbortSignal): Promise<InboxPage> {
        const ordinal = nextOrdinal(this.#context, "read");
        let request = cloneRead(input);
        const before = point(this.#context, "read", "before", ordinal);
        const requestEffects = await applyRequestEffects(
            this.#context,
            before,
            signal,
            request.signature,
        );
        request = { ...request, signature: requestEffects.bytes };
        if (requestEffects.dropped) {
            throw new ChaosInjectedError(before, "Injected dropped transport request");
        }
        let page = clonePage(await this.#context.delegate.read(request, signal));
        for (let copy = 0; copy < requestEffects.duplicateCopies; copy += 1) {
            page = clonePage(await this.#context.delegate.read(request, signal));
        }

        const after = point(this.#context, "read", "after", ordinal);
        for (const effect of chaosEffects(this.#context.schedule.decide(after))) {
            await control(effect, after, this.#context, signal);
            if (effect.type === "drop") {
                page = { ...page, deliveries: [], exhausted: false };
            } else if (effect.type === "duplicate") {
                page = {
                    ...page,
                    deliveries: duplicateAt(page.deliveries, effect.copies, effect.index).map(
                        cloneInboxDelivery,
                    ),
                };
            } else if (effect.type === "reorder") {
                page = {
                    ...page,
                    deliveries: [...page.deliveries].reverse().map(cloneInboxDelivery),
                };
            } else if (effect.type === "truncate") {
                page = {
                    ...page,
                    deliveries: page.deliveries.slice(0, effect.limit).map(cloneInboxDelivery),
                    exhausted: effect.limit >= page.deliveries.length && page.exhausted,
                };
            } else if (effect.type === "corrupt") {
                if (page.deliveries.length < 1) {
                    throw new Error("Chaos corruption requires one inbox delivery");
                }
                const deliveries = page.deliveries.map(cloneInboxDelivery);
                corrupt(deliveries[0]!.delivery.ciphertext, effect);
                page = { ...page, deliveries };
            } else if (effect.type === "replay") {
                if (this.#lastReadPage === undefined) {
                    throw new Error("Chaos read replay requires a prior page");
                }
                page = clonePage(this.#lastReadPage);
            } else if (
                effect.type !== "continue" &&
                effect.type !== "throw" &&
                effect.type !== "crash" &&
                effect.type !== "delay"
            ) {
                unsupported(effect, after);
            }
        }
        this.#lastReadPage = clonePage(page);
        return clonePage(page);
    }

    async acknowledge(
        input: SignedInboxAck,
        signal?: AbortSignal,
    ): Promise<{ readonly removed: number }> {
        const ordinal = nextOrdinal(this.#context, "acknowledge");
        let request = cloneAck(input);
        const before = point(this.#context, "acknowledge", "before", ordinal);
        const requestEffects = await applyRequestEffects(
            this.#context,
            before,
            signal,
            request.signature,
        );
        request = { ...request, signature: requestEffects.bytes };
        if (requestEffects.dropped) {
            throw new ChaosInjectedError(before, "Injected dropped transport request");
        }
        let outcome = await this.#context.delegate.acknowledge(request, signal);
        for (let copy = 0; copy < requestEffects.duplicateCopies; copy += 1) {
            outcome = await this.#context.delegate.acknowledge(request, signal);
        }
        const after = point(this.#context, "acknowledge", "after", ordinal);
        const duplicates = await applyResponseControl(this.#context, after, signal);
        for (let copy = 0; copy < duplicates; copy += 1) {
            await this.#context.delegate.acknowledge(request, signal);
        }
        return { removed: outcome.removed };
    }

    async readDeviceRoster(
        accountKey: Uint8Array,
        signal?: AbortSignal,
    ): Promise<DeliveryDeviceRoster | undefined> {
        return this.#context.delegate.readDeviceRoster?.(accountKey, signal);
    }

    async mutateDeviceRoster(
        delivery: SignedDelivery,
        signal?: AbortSignal,
    ): Promise<DeliveryDeviceRoster> {
        if (this.#context.delegate.mutateDeviceRoster === undefined) {
            throw new Error("Delegate does not support device rosters");
        }
        return this.#context.delegate.mutateDeviceRoster(delivery, signal);
    }

    async *#stream(
        input: SignedInboxRead,
        signal?: AbortSignal,
        hooks: DeliveryStreamHooks = {},
    ): AsyncGenerator<InboxStreamEvent> {
        const delegateStream = this.#context.delegate.stream;
        if (delegateStream === undefined) throw new Error("Delegate does not support streaming");
        const openOrdinal = nextOrdinal(this.#context, "stream.open");
        let request = cloneRead(input);
        const beforeOpen = point(this.#context, "stream.open", "before", openOrdinal);
        const requestEffects = await applyRequestEffects(
            this.#context,
            beforeOpen,
            signal,
            request.signature,
        );
        request = { ...request, signature: requestEffects.bytes };
        if (requestEffects.dropped) {
            throw new ChaosInjectedError(beforeOpen, "Injected dropped stream request");
        }
        const connectedHooks: DeliveryStreamHooks = {
            onConnected: async (): Promise<void> => {
                const ordinal = nextOrdinal(this.#context, "stream.connected");
                const before = point(this.#context, "stream.connected", "before", ordinal);
                await applyResponseControl(this.#context, before, signal);
                await hooks.onConnected?.();
                const after = point(this.#context, "stream.connected", "after", ordinal);
                await applyResponseControl(this.#context, after, signal);
            },
        };
        const iterable = delegateStream.call(
            this.#context.delegate,
            request,
            signal,
            connectedHooks,
        );
        const afterOpen = point(this.#context, "stream.open", "after", openOrdinal);
        await applyResponseControl(this.#context, afterOpen, signal);

        for await (const inputDelivery of iterable) {
            if ("type" in inputDelivery) {
                yield {
                    ...inputDelivery,
                    generation: inputDelivery.generation.slice(),
                };
                continue;
            }
            const ordinal = nextOrdinal(this.#context, "stream.delivery");
            let delivery = cloneInboxDelivery(inputDelivery);
            const before = point(
                this.#context,
                "stream.delivery",
                "before",
                ordinal,
                delivery.delivery,
            );
            let dropped = false;
            let copies = 0;
            for (const effect of chaosEffects(this.#context.schedule.decide(before))) {
                await control(effect, before, this.#context, signal);
                if (effect.type === "drop") {
                    dropped = true;
                } else if (effect.type === "duplicate") {
                    copies += effect.copies;
                } else if (effect.type === "corrupt") {
                    corrupt(delivery.delivery.ciphertext, effect);
                } else if (effect.type === "truncate") {
                    delivery = {
                        ...delivery,
                        delivery: {
                            ...delivery.delivery,
                            ciphertext: delivery.delivery.ciphertext.slice(0, effect.limit),
                        },
                    };
                } else if (effect.type === "replay") {
                    if (this.#lastStreamDelivery === undefined) {
                        throw new Error("Chaos stream replay requires a prior delivery");
                    }
                    delivery = cloneInboxDelivery(this.#lastStreamDelivery);
                } else if (
                    effect.type !== "continue" &&
                    effect.type !== "throw" &&
                    effect.type !== "crash" &&
                    effect.type !== "delay"
                ) {
                    unsupported(effect, before);
                }
            }
            this.#lastStreamDelivery = cloneInboxDelivery(delivery);
            if (!dropped) {
                yield cloneInboxDelivery(delivery);
                for (let copy = 0; copy < copies; copy += 1) {
                    yield cloneInboxDelivery(delivery);
                }
            }
            const after = point(
                this.#context,
                "stream.delivery",
                "after",
                ordinal,
                delivery.delivery,
            );
            await applyResponseControl(this.#context, after, signal);
        }
    }
}
