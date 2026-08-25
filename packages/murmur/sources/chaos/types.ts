import type { DeliveryTransport, SignedDelivery } from "../delivery/index.js";
import type { MurmurStore } from "../storage/index.js";

/** A fault-injection boundary visible to deterministic scenario schedules. */
export type ChaosBoundary = "store" | "transport" | "clock" | "lifecycle";

/** Whether an operation is about to cross or has crossed its delegate boundary. */
export type ChaosPhase = "before" | "after";

/** Redacted metadata for one fault decision. */
export interface ChaosPoint {
    readonly actor: string;
    readonly boundary: ChaosBoundary;
    readonly operation: string;
    readonly phase: ChaosPhase;
    readonly ordinal: number;
    readonly key?: string;
    readonly deliveryId?: string;
    readonly deliveryKind?: number;
}

/** One indivisible injected behavior. */
export type ChaosAtomicEffect =
    | { readonly type: "continue" }
    | { readonly type: "throw"; readonly message: string }
    | { readonly type: "crash"; readonly message: string }
    | { readonly type: "delay"; readonly milliseconds: number }
    | { readonly type: "drop" }
    | { readonly type: "duplicate"; readonly copies: number; readonly index?: number }
    | { readonly type: "corrupt"; readonly offset: number; readonly xor: number }
    | { readonly type: "reorder"; readonly order: "reverse" }
    | { readonly type: "truncate"; readonly limit: number }
    | { readonly type: "replay" };

/** One schedule decision, optionally composing multiple ordered atomic effects. */
export type ChaosEffect =
    | ChaosAtomicEffect
    | { readonly type: "sequence"; readonly effects: readonly ChaosAtomicEffect[] };

/** Exact selector for redacted operation metadata. */
export interface ChaosPointSelector {
    readonly actor?: string;
    readonly boundary?: ChaosBoundary;
    readonly operation?: string;
    readonly phase?: ChaosPhase;
    readonly ordinal?: number;
    readonly key?: string;
    readonly keyPrefix?: string;
    readonly deliveryId?: string;
    readonly deliveryKind?: number;
}

/** One deterministic fault rule. */
export interface ChaosRule {
    readonly id: string;
    readonly selector: ChaosPointSelector;
    readonly effect: ChaosEffect;
    /** Required applications before `assertConsumed` succeeds. Defaults to one. */
    readonly maximumApplications?: number;
    /** Apply on one seeded match in this many. Defaults to every eligible match. */
    readonly oneIn?: number;
}

/** One immutable redacted decision record. */
export interface ChaosTraceEntry extends ChaosPoint {
    readonly index: number;
    readonly effect: string;
    readonly ruleId?: string;
}

/** Deterministic source consulted by fault-injecting boundaries. */
export interface ChaosSchedule {
    decide(point: ChaosPoint): ChaosEffect;
    readonly trace: readonly ChaosTraceEntry[];
    assertConsumed(): void;
}

/** Synchronous monotonic clock for exact protocol time boundaries. */
export interface VirtualClock {
    now(): number;
    advance(milliseconds: number): void;
    set(timestamp: number): void;
}

/** Deterministic delay handler, normally advancing a `VirtualClock` or a gate. */
export type ChaosDelayHandler = (milliseconds: number, point: ChaosPoint) => void | Promise<void>;

/** Construction policy for a fault-injecting store. */
export interface FaultInjectingStoreOptions {
    readonly actor: string;
    readonly delegate: MurmurStore;
    readonly schedule: ChaosSchedule;
    readonly delay?: ChaosDelayHandler;
}

/** Construction policy for a fault-injecting delivery transport. */
export interface FaultInjectingTransportOptions {
    readonly actor: string;
    readonly delegate: DeliveryTransport;
    readonly schedule: ChaosSchedule;
    readonly delay?: ChaosDelayHandler;
    /** Optional public wire classifier; ciphertext is never inspected by default. */
    readonly classifyDelivery?: (delivery: SignedDelivery) => number | undefined;
}

/** Inputs for bounded deterministic convergence. */
export interface SettleChaosOptions<State> {
    readonly maximumRounds: number;
    readonly unchangedRounds?: number;
    readonly act: (round: number) => void | Promise<void>;
    readonly snapshot: () => State | Promise<State>;
    readonly equal?: (left: State, right: State) => boolean;
    readonly describe?: (state: State) => string;
}

/** Successful bounded convergence result. */
export interface SettleChaosResult<State> {
    readonly rounds: number;
    readonly state: State;
}
