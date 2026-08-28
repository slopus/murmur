import type { Context } from "@steve.kite/stdlib";

import type { MurmurStore, StoreScanOptions } from "../../storage/index.js";
import type {
    ChaosAtomicEffect,
    ChaosDelayHandler,
    ChaosPoint,
    ChaosSchedule,
    FaultInjectingStoreOptions,
} from "../types.js";
import { ChaosCrashError, ChaosInjectedError, chaosEffects } from "./seededSchedule.js";

interface StoreFaultContext {
    readonly actor: string;
    readonly schedule: ChaosSchedule;
    readonly delay: ChaosDelayHandler;
    readonly counts: Map<string, number>;
}

function point(
    context: StoreFaultContext,
    operation: string,
    phase: "before" | "after",
    ordinal: number,
    key?: string,
): ChaosPoint {
    return Object.freeze({
        actor: context.actor,
        boundary: "store",
        operation,
        phase,
        ordinal,
        ...(key === undefined ? {} : { key }),
    });
}

function nextOrdinal(context: StoreFaultContext, operation: string): number {
    const ordinal = (context.counts.get(operation) ?? 0) + 1;
    context.counts.set(operation, ordinal);
    return ordinal;
}

async function control(
    effect: ChaosAtomicEffect,
    at: ChaosPoint,
    delay: ChaosDelayHandler,
): Promise<void> {
    if (effect.type === "continue") return;
    if (effect.type === "throw") throw new ChaosInjectedError(at, effect.message);
    if (effect.type === "crash") throw new ChaosCrashError(at, effect.message);
    if (effect.type === "delay") {
        await delay(effect.milliseconds, at);
    }
}

function unsupported(effect: ChaosAtomicEffect, at: ChaosPoint): never {
    throw new Error(
        `Chaos effect ${effect.type} is unsupported for ${at.boundary}:${at.operation}:${at.phase}`,
    );
}

function corrupt(bytes: Uint8Array, effect: Extract<ChaosAtomicEffect, { type: "corrupt" }>): void {
    if (effect.offset >= bytes.length) {
        throw new Error("Chaos corruption offset exceeds the selected byte value");
    }
    bytes[effect.offset] = bytes[effect.offset]! ^ effect.xor;
}

function cloneMap(values: ReadonlyMap<string, Uint8Array>): Map<string, Uint8Array> {
    return new Map([...values].map(([key, value]) => [key, value.slice()] as const));
}

async function beforeRead(
    context: StoreFaultContext,
    at: ChaosPoint,
): Promise<"delegate" | "drop"> {
    for (const effect of chaosEffects(context.schedule.decide(at))) {
        await control(effect, at, context.delay);
        if (effect.type === "drop") return "drop";
        if (
            effect.type !== "continue" &&
            effect.type !== "throw" &&
            effect.type !== "crash" &&
            effect.type !== "delay"
        ) {
            unsupported(effect, at);
        }
    }
    return "delegate";
}

async function afterBytes(
    context: StoreFaultContext,
    at: ChaosPoint,
    input: Uint8Array | undefined,
): Promise<Uint8Array | undefined> {
    let value = input?.slice();
    for (const effect of chaosEffects(context.schedule.decide(at))) {
        await control(effect, at, context.delay);
        if (effect.type === "drop") {
            value = undefined;
        } else if (effect.type === "corrupt" && value !== undefined) {
            corrupt(value, effect);
        } else if (effect.type === "truncate" && value !== undefined) {
            value = value.slice(0, effect.limit);
        } else if (
            effect.type !== "continue" &&
            effect.type !== "throw" &&
            effect.type !== "crash" &&
            effect.type !== "delay" &&
            effect.type !== "corrupt" &&
            effect.type !== "truncate"
        ) {
            unsupported(effect, at);
        }
    }
    return value;
}

async function afterMap(
    context: StoreFaultContext,
    at: ChaosPoint,
    input: ReadonlyMap<string, Uint8Array>,
): Promise<ReadonlyMap<string, Uint8Array>> {
    let value = cloneMap(input);
    for (const effect of chaosEffects(context.schedule.decide(at))) {
        await control(effect, at, context.delay);
        if (effect.type === "drop") {
            value = new Map();
        } else if (effect.type === "truncate") {
            value = new Map([...value].slice(0, effect.limit));
        } else if (effect.type === "reorder") {
            value = new Map([...value].reverse());
        } else if (effect.type === "corrupt") {
            const first = value.entries().next().value as [string, Uint8Array] | undefined;
            if (first === undefined) {
                throw new Error("Chaos corruption requires a selected store value");
            }
            corrupt(first[1], effect);
        } else if (
            effect.type !== "continue" &&
            effect.type !== "throw" &&
            effect.type !== "crash" &&
            effect.type !== "delay"
        ) {
            unsupported(effect, at);
        }
    }
    return value;
}

class FaultInjectingStoreView implements MurmurStore {
    readonly #delegate: MurmurStore;
    readonly #context: StoreFaultContext;
    readonly #scope: "store" | "transaction";

    constructor(delegate: MurmurStore, context: StoreFaultContext, scope: "store" | "transaction") {
        this.#delegate = delegate;
        this.#context = context;
        this.#scope = scope;
    }

    async get(ctx: Context, key: string): Promise<Uint8Array | undefined> {
        const operation = this.#operation("get");
        const ordinal = nextOrdinal(this.#context, operation);
        if (
            (await beforeRead(
                this.#context,
                point(this.#context, operation, "before", ordinal, key),
            )) === "drop"
        ) {
            return undefined;
        }
        const value = await this.#delegate.get(ctx, key);
        return afterBytes(
            this.#context,
            point(this.#context, operation, "after", ordinal, key),
            value,
        );
    }

    async set(ctx: Context, key: string, input: Uint8Array): Promise<void> {
        const operation = this.#operation("set");
        const ordinal = nextOrdinal(this.#context, operation);
        const before = point(this.#context, operation, "before", ordinal, key);
        let value = input.slice();
        let dropped = false;
        for (const effect of chaosEffects(this.#context.schedule.decide(before))) {
            await control(effect, before, this.#context.delay);
            if (effect.type === "drop") {
                dropped = true;
            } else if (effect.type === "corrupt") {
                corrupt(value, effect);
            } else if (effect.type === "truncate") {
                value = value.slice(0, effect.limit);
            } else if (
                effect.type !== "continue" &&
                effect.type !== "throw" &&
                effect.type !== "crash" &&
                effect.type !== "delay"
            ) {
                unsupported(effect, before);
            }
        }
        if (!dropped) await this.#delegate.set(ctx, key, value);
        await this.#afterMutation(operation, ordinal, key);
    }

    async delete(ctx: Context, key: string): Promise<void> {
        const operation = this.#operation("delete");
        const ordinal = nextOrdinal(this.#context, operation);
        const before = point(this.#context, operation, "before", ordinal, key);
        let dropped = false;
        for (const effect of chaosEffects(this.#context.schedule.decide(before))) {
            await control(effect, before, this.#context.delay);
            if (effect.type === "drop") {
                dropped = true;
            } else if (
                effect.type !== "continue" &&
                effect.type !== "throw" &&
                effect.type !== "crash" &&
                effect.type !== "delay"
            ) {
                unsupported(effect, before);
            }
        }
        if (!dropped) await this.#delegate.delete(ctx, key);
        await this.#afterMutation(operation, ordinal, key);
    }

    async list(ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        const operation = this.#operation("list");
        const ordinal = nextOrdinal(this.#context, operation);
        if (
            (await beforeRead(
                this.#context,
                point(this.#context, operation, "before", ordinal, prefix),
            )) === "drop"
        ) {
            return new Map();
        }
        return afterMap(
            this.#context,
            point(this.#context, operation, "after", ordinal, prefix),
            await this.#delegate.list(ctx, prefix),
        );
    }

    async scan(
        ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        const operation = this.#operation("scan");
        const ordinal = nextOrdinal(this.#context, operation);
        if (
            (await beforeRead(
                this.#context,
                point(this.#context, operation, "before", ordinal, prefix),
            )) === "drop"
        ) {
            return new Map();
        }
        return afterMap(
            this.#context,
            point(this.#context, operation, "after", ordinal, prefix),
            await this.#delegate.scan(ctx, prefix, options),
        );
    }

    async tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result> {
        return this.#delegate.tx(ctx, operation);
    }

    async #afterMutation(operation: string, ordinal: number, key: string): Promise<void> {
        const after = point(this.#context, operation, "after", ordinal, key);
        for (const effect of chaosEffects(this.#context.schedule.decide(after))) {
            await control(effect, after, this.#context.delay);
            if (effect.type === "drop") {
                throw new ChaosInjectedError(after, "Injected lost store response");
            }
            if (
                effect.type !== "continue" &&
                effect.type !== "throw" &&
                effect.type !== "crash" &&
                effect.type !== "delay"
            ) {
                unsupported(effect, after);
            }
        }
    }

    #operation(name: string): string {
        return this.#scope === "store" ? name : `transaction.${name}`;
    }
}

/** MurmurStore boundary wrapper with deterministic transaction and byte faults. */
export class FaultInjectingMurmurStore implements MurmurStore {
    readonly #delegate: MurmurStore;
    readonly #context: StoreFaultContext;
    readonly #activeTransactions = new WeakMap<Context, number>();

    constructor(options: FaultInjectingStoreOptions) {
        if (options.actor.length < 1) throw new Error("Chaos store actor cannot be empty");
        this.#delegate = options.delegate;
        this.#context = {
            actor: options.actor,
            schedule: options.schedule,
            delay: options.delay ?? (() => undefined),
            counts: new Map(),
        };
    }

    /** Defensive snapshot of per-operation call ordinals. */
    get operationCounts(): ReadonlyMap<string, number> {
        return new Map(this.#context.counts);
    }

    async get(ctx: Context, key: string): Promise<Uint8Array | undefined> {
        return this.#view(ctx).get(ctx, key);
    }

    async set(ctx: Context, key: string, value: Uint8Array): Promise<void> {
        await this.#view(ctx).set(ctx, key, value);
    }

    async delete(ctx: Context, key: string): Promise<void> {
        await this.#view(ctx).delete(ctx, key);
    }

    async list(ctx: Context, prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#view(ctx).list(ctx, prefix);
    }

    async scan(
        ctx: Context,
        prefix: string,
        options: StoreScanOptions,
    ): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#view(ctx).scan(ctx, prefix, options);
    }

    async tx<Result>(ctx: Context, operation: (ctx: Context) => Promise<Result>): Promise<Result> {
        const ordinal = nextOrdinal(this.#context, "transaction");
        const before = point(this.#context, "transaction", "before", ordinal);
        for (const effect of chaosEffects(this.#context.schedule.decide(before))) {
            await control(effect, before, this.#context.delay);
            if (
                effect.type !== "continue" &&
                effect.type !== "throw" &&
                effect.type !== "crash" &&
                effect.type !== "delay"
            ) {
                unsupported(effect, before);
            }
        }

        const result = await this.#delegate.tx(ctx, async (tx) => {
            this.#activeTransactions.set(tx, (this.#activeTransactions.get(tx) ?? 0) + 1);
            try {
                const value = await operation(tx);
                const commitOrdinal = nextOrdinal(this.#context, "transaction.commit");
                const commit = point(this.#context, "transaction.commit", "before", commitOrdinal);
                for (const effect of chaosEffects(this.#context.schedule.decide(commit))) {
                    await control(effect, commit, this.#context.delay);
                    if (
                        effect.type !== "continue" &&
                        effect.type !== "throw" &&
                        effect.type !== "crash" &&
                        effect.type !== "delay"
                    ) {
                        unsupported(effect, commit);
                    }
                }
                return value;
            } finally {
                const depth = this.#activeTransactions.get(tx) ?? 1;
                if (depth === 1) {
                    this.#activeTransactions.delete(tx);
                } else {
                    this.#activeTransactions.set(tx, depth - 1);
                }
            }
        });

        const after = point(this.#context, "transaction", "after", ordinal);
        for (const effect of chaosEffects(this.#context.schedule.decide(after))) {
            await control(effect, after, this.#context.delay);
            if (effect.type === "drop") {
                throw new ChaosInjectedError(after, "Injected lost transaction response");
            }
            if (
                effect.type !== "continue" &&
                effect.type !== "throw" &&
                effect.type !== "crash" &&
                effect.type !== "delay"
            ) {
                unsupported(effect, after);
            }
        }
        return result;
    }

    #view(ctx: Context): FaultInjectingStoreView {
        return new FaultInjectingStoreView(
            this.#delegate,
            this.#context,
            (this.#activeTransactions.get(ctx) ?? 0) > 0 ? "transaction" : "store",
        );
    }
}
