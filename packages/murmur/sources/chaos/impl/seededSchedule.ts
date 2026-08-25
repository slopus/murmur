import type {
    ChaosAtomicEffect,
    ChaosEffect,
    ChaosPoint,
    ChaosPointSelector,
    ChaosRule,
    ChaosTraceEntry,
    SettleChaosOptions,
    SettleChaosResult,
} from "../types.js";

const CONTINUE: ChaosAtomicEffect = Object.freeze({ type: "continue" });
const UINT32_RANGE = 0x1_0000_0000;

function unsigned(value: number, label: string): number {
    if (!Number.isSafeInteger(value) || value < 0 || value >= UINT32_RANGE) {
        throw new Error(`${label} must be an unsigned 32-bit integer`);
    }
    return value >>> 0;
}

function hashLabel(seed: number, label: string): number {
    let hash = (0x811c9dc5 ^ seed) >>> 0;
    for (let index = 0; index < label.length; index += 1) {
        const code = label.charCodeAt(index);
        hash ^= code & 0xff;
        hash = Math.imul(hash, 0x01000193) >>> 0;
        hash ^= code >>> 8;
        hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash;
}

function validateAtomicEffect(effect: ChaosAtomicEffect): void {
    if (effect.type === "delay") {
        if (!Number.isSafeInteger(effect.milliseconds) || effect.milliseconds < 0) {
            throw new Error("Chaos delay must be a non-negative safe integer");
        }
    }
    if (effect.type === "duplicate") {
        if (!Number.isSafeInteger(effect.copies) || effect.copies < 1 || effect.copies > 10_000) {
            throw new Error("Chaos duplicate copies must be between 1 and 10,000");
        }
        if (
            effect.index !== undefined &&
            (!Number.isSafeInteger(effect.index) || effect.index < 0)
        ) {
            throw new Error("Chaos duplicate index must be a non-negative safe integer");
        }
    }
    if (effect.type === "corrupt") {
        if (!Number.isSafeInteger(effect.offset) || effect.offset < 0) {
            throw new Error("Chaos corruption offset must be a non-negative safe integer");
        }
        if (!Number.isSafeInteger(effect.xor) || effect.xor < 1 || effect.xor > 255) {
            throw new Error("Chaos corruption xor must be between 1 and 255");
        }
    }
    if (effect.type === "truncate") {
        if (!Number.isSafeInteger(effect.limit) || effect.limit < 0) {
            throw new Error("Chaos truncation limit must be a non-negative safe integer");
        }
    }
}

function validateEffect(effect: ChaosEffect): void {
    if (effect.type !== "sequence") {
        validateAtomicEffect(effect);
        return;
    }
    if (effect.effects.length < 1) {
        throw new Error("Chaos effect sequence cannot be empty");
    }
    for (const item of effect.effects) validateAtomicEffect(item);
}

function selectorMatches(selector: ChaosPointSelector, point: ChaosPoint): boolean {
    return !(
        (selector.actor !== undefined && selector.actor !== point.actor) ||
        (selector.boundary !== undefined && selector.boundary !== point.boundary) ||
        (selector.operation !== undefined && selector.operation !== point.operation) ||
        (selector.phase !== undefined && selector.phase !== point.phase) ||
        (selector.ordinal !== undefined && selector.ordinal !== point.ordinal) ||
        (selector.key !== undefined && selector.key !== point.key) ||
        (selector.keyPrefix !== undefined && point.key?.startsWith(selector.keyPrefix) !== true) ||
        (selector.deliveryId !== undefined && selector.deliveryId !== point.deliveryId) ||
        (selector.deliveryKind !== undefined && selector.deliveryKind !== point.deliveryKind)
    );
}

function effectName(effect: ChaosEffect): string {
    return effect.type === "sequence"
        ? `sequence(${effect.effects.map((item) => item.type).join(",")})`
        : effect.type;
}

function traceEntry(
    index: number,
    point: ChaosPoint,
    effect: ChaosEffect,
    ruleId?: string,
): ChaosTraceEntry {
    return Object.freeze({
        index,
        actor: point.actor,
        boundary: point.boundary,
        operation: point.operation,
        phase: point.phase,
        ordinal: point.ordinal,
        ...(point.key === undefined ? {} : { key: point.key }),
        ...(point.deliveryId === undefined ? {} : { deliveryId: point.deliveryId }),
        ...(point.deliveryKind === undefined ? {} : { deliveryKind: point.deliveryKind }),
        effect: effectName(effect),
        ...(ruleId === undefined ? {} : { ruleId }),
    });
}

/** Expand one decision into its ordered atomic effects. */
export function chaosEffects(effect: ChaosEffect): readonly ChaosAtomicEffect[] {
    return effect.type === "sequence" ? effect.effects : [effect];
}

/** Typed deterministic boundary failure. */
export class ChaosInjectedError extends Error {
    readonly point: ChaosPoint;

    constructor(point: ChaosPoint, message: string) {
        super(message);
        this.name = "ChaosInjectedError";
        this.point = point;
    }
}

/** Typed sentinel instructing a scenario driver to abandon one client instance. */
export class ChaosCrashError extends ChaosInjectedError {
    constructor(point: ChaosPoint, message: string) {
        super(point, message);
        this.name = "ChaosCrashError";
    }
}

/** Platform-independent Mulberry32 source with non-consuming labeled forks. */
export class SeededRandom {
    readonly #seed: number;
    #state: number;

    constructor(seed: number) {
        this.#seed = unsigned(seed, "Chaos seed");
        this.#state = this.#seed;
    }

    /** Produce the next unsigned 32-bit value. */
    nextUint32(): number {
        this.#state = (this.#state + 0x6d2b79f5) >>> 0;
        let value = this.#state;
        value = Math.imul(value ^ (value >>> 15), value | 1);
        value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
        return (value ^ (value >>> 14)) >>> 0;
    }

    /** Select an integer in the half-open `[minimum, maximumExclusive)` range. */
    integer(minimum: number, maximumExclusive: number): number {
        if (
            !Number.isSafeInteger(minimum) ||
            !Number.isSafeInteger(maximumExclusive) ||
            minimum < 0 ||
            maximumExclusive <= minimum ||
            maximumExclusive - minimum > UINT32_RANGE
        ) {
            throw new Error("Invalid seeded integer range");
        }
        const width = maximumExclusive - minimum;
        return minimum + Math.floor((this.nextUint32() * width) / UINT32_RANGE);
    }

    /** Return true for one deterministic choice in `denominator`. */
    oneIn(denominator: number): boolean {
        if (!Number.isSafeInteger(denominator) || denominator < 1) {
            throw new Error("Seeded denominator must be a positive safe integer");
        }
        return this.integer(0, denominator) === 0;
    }

    /** Derive an actor/scenario stream without consuming this stream. */
    fork(label: string): SeededRandom {
        if (label.length < 1) throw new Error("Seeded fork label cannot be empty");
        return new SeededRandom(hashLabel(this.#seed, label));
    }
}

interface RuleState {
    readonly rule: ChaosRule;
    applications: number;
}

/** Deterministic exact-rule schedule with optional seeded eligibility. */
export class SeededChaosSchedule {
    readonly #seed: number;
    readonly #random: SeededRandom;
    readonly #rules: RuleState[];
    readonly #trace: ChaosTraceEntry[] = [];

    constructor(seed: number, rules: readonly ChaosRule[] = []) {
        this.#seed = unsigned(seed, "Chaos seed");
        this.#random = new SeededRandom(this.#seed);
        const ids = new Set<string>();
        this.#rules = rules.map((rule) => {
            if (rule.id.length < 1 || ids.has(rule.id)) {
                throw new Error("Chaos rule IDs must be non-empty and unique");
            }
            ids.add(rule.id);
            validateEffect(rule.effect);
            const maximum = rule.maximumApplications ?? 1;
            if (!Number.isSafeInteger(maximum) || maximum < 1) {
                throw new Error("Chaos rule maximum applications must be positive");
            }
            if (rule.oneIn !== undefined && (!Number.isSafeInteger(rule.oneIn) || rule.oneIn < 1)) {
                throw new Error("Chaos rule oneIn must be a positive safe integer");
            }
            return { rule, applications: 0 };
        });
    }

    /** Immutable copy of all reached decision points. */
    get trace(): readonly ChaosTraceEntry[] {
        return this.#trace.slice();
    }

    /** Select one effect and append a redacted trace entry. */
    decide(point: ChaosPoint): ChaosEffect {
        for (const state of this.#rules) {
            const maximum = state.rule.maximumApplications ?? 1;
            if (
                state.applications >= maximum ||
                !selectorMatches(state.rule.selector, point) ||
                (state.rule.oneIn !== undefined && !this.#random.oneIn(state.rule.oneIn))
            ) {
                continue;
            }
            state.applications += 1;
            this.#trace.push(
                traceEntry(this.#trace.length, point, state.rule.effect, state.rule.id),
            );
            return state.rule.effect;
        }
        this.#trace.push(traceEntry(this.#trace.length, point, CONTINUE));
        return CONTINUE;
    }

    /** Fail when any configured exact rule did not reach its required hit count. */
    assertConsumed(): void {
        const missing = this.#rules
            .filter((state) => state.applications !== (state.rule.maximumApplications ?? 1))
            .map(
                (state) =>
                    `${state.rule.id} (${state.applications}/${state.rule.maximumApplications ?? 1})`,
            );
        if (missing.length > 0) {
            const observed = this.#trace
                .slice(-20)
                .map(
                    (entry) =>
                        `${entry.actor}:${entry.boundary}:${entry.operation}:${entry.phase}#${entry.ordinal}`,
                )
                .join(", ");
            throw new Error(
                `Unconsumed chaos rules: ${missing.join(", ")}; observed: ${observed || "none"}`,
            );
        }
    }

    /** Derive an independent schedule without consuming this schedule's random stream. */
    fork(label: string, rules: readonly ChaosRule[] = []): SeededChaosSchedule {
        if (label.length < 1) throw new Error("Chaos schedule fork label cannot be empty");
        return new SeededChaosSchedule(hashLabel(this.#seed, label), rules);
    }
}

/** Drive explicit actions until snapshots remain unchanged for a bounded number of rounds. */
export async function settleChaos<State>(
    options: SettleChaosOptions<State>,
): Promise<SettleChaosResult<State>> {
    if (!Number.isSafeInteger(options.maximumRounds) || options.maximumRounds < 1) {
        throw new Error("Maximum chaos settle rounds must be positive");
    }
    const required = options.unchangedRounds ?? 2;
    if (!Number.isSafeInteger(required) || required < 1 || required > options.maximumRounds) {
        throw new Error("Unchanged chaos settle rounds are invalid");
    }
    const equal = options.equal ?? Object.is;
    let previous = await options.snapshot();
    let unchanged = 0;
    for (let round = 1; round <= options.maximumRounds; round += 1) {
        await options.act(round);
        const current = await options.snapshot();
        if (equal(previous, current)) {
            unchanged += 1;
            if (unchanged >= required) return { rounds: round, state: current };
        } else {
            unchanged = 0;
        }
        previous = current;
    }
    const description = options.describe?.(previous) ?? String(previous);
    throw new Error(
        `Chaos system did not settle within ${options.maximumRounds} rounds; final=${description}`,
    );
}
