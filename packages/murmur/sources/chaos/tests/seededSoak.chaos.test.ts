/**
 * Deterministic composed chaos profiles.
 *
 * Default: 25 seeds × 100 actions, replayed in fresh harnesses.
 * `MURMUR_CHAOS_PROFILE=standard`: seeds 0–255 × 200 actions.
 * `MURMUR_CHAOS_PROFILE=extended MURMUR_CHAOS_SEED_START=<uint32>`:
 * 1,000 seeds × 500 actions with one progress line per seed.
 */
import {
    DELIVERY_RETENTION_MILLISECONDS,
    RelayService,
    SqliteRelayStore,
    createRelayFetchHandler,
} from "@slopus/murmur-relay";
import { describe, expect, test } from "vitest";
import {
    destroyIdentity,
    generateIdentityKeyPair,
    hashBytes,
    type IdentityKeyPair,
} from "../../crypto/index.js";
import {
    HttpDeliveryTransport,
    createSignedDelivery,
    createSignedInboxAck,
    createSignedInboxRead,
    type DeliveryFetch,
    type SignedDelivery,
} from "../../delivery/index.js";
import {
    MurmurClient,
    MurmurResetRequiredError,
    type MurmurResetEvent,
    type MurmurSession,
} from "../../sessions/index.js";
import { MemoryMurmurStore } from "../../storage/index.js";
import {
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import {
    FaultInjectingMurmurStore,
    ManualVirtualClock,
    SeededChaosSchedule,
    SeededRandom,
} from "../index.js";

const NOW = 1_700_000_000_000;
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const RETENTION = 180 * DAY;
const ADMISSION = 210 * DAY;
const TRACE_LIMIT = 64 * 1_024;
const MAXIMUM_QUEUE_ITEMS = 512;
const FAST_SEEDS = [
    0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1_597, 2_584, 4_181, 6_765,
    10_946, 17_711, 28_657, 46_368, 75_025,
] as const;

interface VitestRuntimeRpcMethod {
    (...arguments_: readonly unknown[]): Promise<unknown>;
    readonly asEvent: (...arguments_: readonly unknown[]) => void;
}

interface VitestWorkerState {
    rpc: object;
}

// Vitest 3.2.7 times out waiting for a reporter acknowledgement when one test
// legitimately runs longer than 60 seconds. The event form preserves the same
// ordered task update without retaining the acknowledgement promise. This is
// isolated to the worker executing this opt-in soak file.
const workerState = (
    globalThis as typeof globalThis & { readonly __vitest_worker__?: VitestWorkerState }
).__vitest_worker__;
if (workerState !== undefined) {
    const delegate = workerState.rpc;
    workerState.rpc = new Proxy(delegate, {
        get(target, property, receiver): unknown {
            const value = Reflect.get(target, property, receiver) as unknown;
            if (property !== "onTaskUpdate" || typeof value !== "function") return value;
            const update = value as VitestRuntimeRpcMethod;
            return (...arguments_: readonly unknown[]): Promise<void> => {
                update.asEvent(...arguments_);
                return Promise.resolve();
            };
        },
    });
}

type InvariantId =
    | "I01"
    | "I02"
    | "I03"
    | "I04"
    | "I05"
    | "I06"
    | "I07"
    | "I08"
    | "I09"
    | "I10"
    | "I11"
    | "I12"
    | "I13"
    | "I14"
    | "I15"
    | "I16"
    | "I17"
    | "I18"
    | "I19"
    | "I20"
    | "I21"
    | "I22"
    | "I23"
    | "I24";

const INVARIANTS: readonly InvariantId[] = Array.from(
    { length: 24 },
    (_, index) => `I${String(index + 1).padStart(2, "0")}` as InvariantId,
);

type ProfileName = "fast" | "standard" | "extended";
type ActorName = `device-${number}`;
type AccountName = `account-${number}`;
type SessionName = `session-${number}`;
type ResetPhase =
    | "active"
    | "recorded"
    | "callback-pending"
    | "purged"
    | "announced"
    | "re-admitted";
type IntentState = "live" | "completed" | "noop" | "issue" | "superseded-unreported";

interface ProfileConfig {
    readonly name: ProfileName;
    readonly seeds: readonly number[];
    readonly actions: number;
    readonly actors: number;
    readonly sessions: number;
}

interface SessionPolicy {
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
}

interface SessionModel {
    readonly name: SessionName;
    readonly owner: AccountName;
    readonly descriptor: string;
    readonly members: Set<AccountName>;
    readonly admins: Set<AccountName>;
    readonly removals: Map<AccountName, number>;
    policy: SessionPolicy;
    epoch: number;
    privateRevision: number;
    privateDigest: string;
}

interface ResetSnapshot {
    readonly id: string;
    readonly generation: Uint8Array;
    readonly head: string | null;
    readonly headSequence: number;
    readonly sessions: readonly SessionName[];
}

interface ActorModel {
    readonly name: ActorName;
    readonly account: AccountName;
    readonly identity: IdentityKeyPair;
    readonly identityTag: string;
    readonly store: MemoryMurmurStore;
    active: boolean;
    revoked: boolean;
    crashed: boolean;
    publishPartitioned: boolean;
    readPartitioned: boolean;
    ackPartitioned: boolean;
    generation: Uint8Array | undefined;
    generationIndex: number;
    sequence: number;
    acknowledgedSequence: number;
    cursor: string | null;
    lastEventId: string | null;
    pendingAck: string | null;
    reset: ResetPhase;
    resetSnapshot: ResetSnapshot | undefined;
    resetCallbackAttempts: number;
    purgeCount: number;
    resetAnnouncements: number;
    readonly observedEpochs: Map<SessionName, number>;
    readonly effects: Set<string>;
}

interface IntentModel {
    readonly id: string;
    readonly session: SessionName;
    readonly creator: AccountName;
    readonly kind: "add" | "remove" | "grant" | "revoke" | "policy" | "leave";
    readonly target: AccountName;
    readonly parentEpoch: number;
    readonly removalGeneration: number;
    readonly knownUnreported: boolean;
    state: IntentState;
}

interface LabelModel {
    readonly label: string;
    readonly session: SessionName;
    readonly sender: ActorName;
    readonly required: Set<ActorName>;
    readonly forbidden: Set<ActorName>;
    readonly delivery: SignedDelivery;
    eventId: string | undefined;
    ambiguous: boolean;
}

interface RaceModel {
    readonly id: string;
    readonly session: SessionName;
    readonly parentEpoch: number;
    readonly candidates: readonly ActorName[];
    readonly eventIds: readonly string[];
    readonly winner: ActorName;
    readonly replacementWelcome: boolean;
    readonly stagedLabel: string;
}

interface NormalizedResult {
    readonly actions: readonly SoakAction[];
    readonly effects: readonly string[];
    readonly relayRelations: readonly string[];
    readonly terminal: string;
    readonly traceDigest: string;
    readonly invariants: readonly InvariantId[];
}

type SoakAction =
    | {
          readonly kind: "create-session";
          readonly session: number;
          readonly policy: SessionPolicy;
      }
    | {
          readonly kind: "send";
          readonly actor: number;
          readonly session: number;
          readonly label: string;
      }
    | { readonly kind: "sync"; readonly actor: number }
    | { readonly kind: "sync-all"; readonly order: readonly number[] }
    | {
          readonly kind: "intent";
          readonly actor: number;
          readonly session: number;
          readonly operation: IntentModel["kind"];
          readonly targetAccount: number;
      }
    | {
          readonly kind: "invalid-intent";
          readonly actor: number;
          readonly session: number;
          readonly attack: "remove-owner" | "policy-by-member";
      }
    | {
          readonly kind: "race";
          readonly session: number;
          readonly actors: readonly [number, number];
          readonly replacementWelcome: boolean;
          readonly label: string;
      }
    | { readonly kind: "crash" | "reopen"; readonly actor: number }
    | {
          readonly kind: "partition" | "heal";
          readonly actor: number;
          readonly boundary: "publish" | "read" | "ack";
      }
    | {
          readonly kind: "ambiguous-publish";
          readonly actor: number;
          readonly session: number;
          readonly label: string;
      }
    | { readonly kind: "duplicate-read" | "lost-ack"; readonly actor: number }
    | {
          readonly kind: "store-cut";
          readonly actor: number;
          readonly mode: "rollback" | "lost-response";
          readonly ordinal: number;
      }
    | { readonly kind: "provision-device" | "revoke-device"; readonly actor: number }
    | { readonly kind: "retention-boundary"; readonly actor: number }
    | { readonly kind: "continuity-loss"; readonly actor: number }
    | {
          readonly kind: "reset-callback-fail" | "reset-purge" | "reset-announce" | "re-admit";
          readonly actor: number;
      }
    | {
          readonly kind: "advance";
          readonly boundary: "five-minute" | "180-day" | "210-day";
          readonly delta: -1 | 0 | 1;
      }
    | { readonly kind: "private-roster"; readonly session: number }
    | {
          readonly kind: "mutation";
          readonly family: "delivery" | "commit" | "welcome" | "provisioning";
      }
    | { readonly kind: "noop" };

class SoakInvariantError extends Error {
    readonly invariant: InvariantId;
    readonly classification: string;

    constructor(invariant: InvariantId, classification: string, message: string) {
        super(`${invariant}/${classification}: ${message}`);
        this.name = "SoakInvariantError";
        this.invariant = invariant;
        this.classification = classification;
    }
}

function environment(): Readonly<Record<string, string | undefined>> {
    return (
        (
            globalThis as typeof globalThis & {
                readonly process?: { readonly env?: Readonly<Record<string, string | undefined>> };
            }
        ).process?.env ?? {}
    );
}

function uint32(value: string | undefined, fallback: number): number {
    if (value === undefined) return fallback;
    if (!/^\d+$/.test(value)) throw new Error("MURMUR_CHAOS_SEED_START must be uint32 decimal");
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffff_ffff) {
        throw new Error("MURMUR_CHAOS_SEED_START must be uint32 decimal");
    }
    return parsed >>> 0;
}

function selectedProfile(): ProfileConfig {
    const values = environment();
    const name = values.MURMUR_CHAOS_PROFILE ?? "fast";
    if (name === "fast") {
        return { name, seeds: FAST_SEEDS, actions: 100, actors: 5, sessions: 3 };
    }
    if (name === "standard") {
        return {
            name,
            seeds: Array.from({ length: 256 }, (_, seed) => seed),
            actions: 200,
            actors: 12,
            sessions: 5,
        };
    }
    if (name === "extended") {
        const start = uint32(values.MURMUR_CHAOS_SEED_START, 0);
        return {
            name,
            seeds: Array.from({ length: 1_000 }, (_, offset) => (start + offset) >>> 0),
            actions: 500,
            actors: 5,
            sessions: 3,
        };
    }
    throw new Error("MURMUR_CHAOS_PROFILE must be fast, standard, or extended");
}

function actorName(index: number): ActorName {
    return `device-${index}`;
}

function accountName(index: number): AccountName {
    return `account-${index}`;
}

function sessionName(index: number): SessionName {
    return `session-${index}`;
}

function compareNumbers(left: number, right: number): number {
    return left - right;
}

function generateActions(seed: number, config: ProfileConfig): readonly SoakAction[] {
    const random = new SeededRandom(seed);
    const actions: SoakAction[] = [];
    for (let session = 0; session < config.sessions; session += 1) {
        actions.push({
            kind: "create-session",
            session,
            policy: {
                adminsAssignAdmins: (session & 1) === 1,
                anyoneCanAddMembers: (session & 2) === 2 || session === 1,
            },
        });
    }
    for (let index = 0; index < 10; index += 1) {
        actions.push({
            kind: "send",
            actor: index % 2,
            session: index % config.sessions,
            label: `seed-${seed}-send-${index}`,
        });
    }
    actions.push(
        { kind: "intent", actor: 0, session: 0, operation: "add", targetAccount: 3 },
        { kind: "intent", actor: 0, session: 0, operation: "grant", targetAccount: 1 },
        { kind: "intent", actor: 0, session: 0, operation: "policy", targetAccount: 0 },
        { kind: "intent", actor: 0, session: 0, operation: "add", targetAccount: 1 },
        { kind: "intent", actor: 0, session: 0, operation: "remove", targetAccount: 2 },
        { kind: "invalid-intent", actor: 0, session: 0, attack: "remove-owner" },
        { kind: "invalid-intent", actor: 2, session: 0, attack: "policy-by-member" },
        {
            kind: "race",
            session: 0,
            actors: [0, 1],
            replacementWelcome: false,
            label: `seed-${seed}-staged-role`,
        },
        {
            kind: "race",
            session: Math.min(1, config.sessions - 1),
            actors: [1, 2],
            replacementWelcome: true,
            label: `seed-${seed}-staged-welcome`,
        },
        { kind: "crash", actor: 2 },
        { kind: "reopen", actor: 2 },
        { kind: "partition", actor: 1, boundary: "publish" },
        {
            kind: "send",
            actor: 1,
            session: 0,
            label: `seed-${seed}-partitioned-send`,
        },
        { kind: "heal", actor: 1, boundary: "publish" },
        {
            kind: "ambiguous-publish",
            actor: 0,
            session: 0,
            label: `seed-${seed}-lost-publish`,
        },
        { kind: "duplicate-read", actor: 0 },
        { kind: "lost-ack", actor: 1 },
        { kind: "store-cut", actor: 0, mode: "rollback", ordinal: 0 },
        { kind: "store-cut", actor: 0, mode: "lost-response", ordinal: 1 },
        { kind: "provision-device", actor: Math.min(4, config.actors - 1) },
        { kind: "sync-all", order: Array.from({ length: config.actors }, (_, index) => index) },
        { kind: "retention-boundary", actor: 2 },
        { kind: "continuity-loss", actor: 3 },
        { kind: "reset-callback-fail", actor: 3 },
        { kind: "reset-purge", actor: 3 },
        { kind: "reset-announce", actor: 3 },
        { kind: "re-admit", actor: 3 },
        { kind: "revoke-device", actor: Math.min(4, config.actors - 1) },
        { kind: "advance", boundary: "five-minute", delta: -1 },
        { kind: "advance", boundary: "five-minute", delta: 0 },
        { kind: "advance", boundary: "five-minute", delta: 1 },
        { kind: "advance", boundary: "210-day", delta: -1 },
        { kind: "advance", boundary: "210-day", delta: 0 },
        { kind: "advance", boundary: "210-day", delta: 1 },
        { kind: "private-roster", session: 0 },
        { kind: "mutation", family: "delivery" },
        { kind: "mutation", family: "commit" },
        { kind: "mutation", family: "welcome" },
        { kind: "mutation", family: "provisioning" },
    );
    while (actions.length < config.actions) {
        switch (random.integer(0, 8)) {
            case 0:
                actions.push({ kind: "noop" });
                break;
            case 1:
                actions.push({ kind: "noop" });
                break;
            case 2:
                actions.push({
                    kind: "private-roster",
                    session: random.integer(0, config.sessions),
                });
                break;
            case 3:
                actions.push({
                    kind: "intent",
                    actor: 0,
                    session: random.integer(0, config.sessions),
                    operation: "policy",
                    targetAccount: 0,
                });
                break;
            case 4:
                actions.push({ kind: "mutation", family: "provisioning" });
                break;
            case 5:
                actions.push({ kind: "mutation", family: "delivery" });
                break;
            case 6:
                actions.push({ kind: "advance", boundary: "five-minute", delta: -1 });
                break;
            default:
                actions.push({ kind: "noop" });
        }
    }
    return Object.freeze(actions.slice(0, config.actions));
}

function hashText(value: string): string {
    return encodeBase64Url(hashBytes(utf8Encode(value)));
}

function actionText(action: SoakAction): string {
    return JSON.stringify(action);
}

type RelayPage = Awaited<ReturnType<RelayService["readQueue"]>>;

class SoakHarness {
    readonly #seed: number;
    readonly #scheduleSeed: number;
    readonly #config: ProfileConfig;
    readonly #clock = new ManualVirtualClock(NOW);
    readonly #relay: RelayService;
    readonly #actors: ActorModel[];
    readonly #sessions = new Map<SessionName, SessionModel>();
    readonly #intents: IntentModel[] = [];
    readonly #labels = new Map<string, LabelModel>();
    readonly #races: RaceModel[] = [];
    readonly #trace: string[] = [];
    readonly #relayRelations: string[] = [];
    readonly #covered = new Set<InvariantId>();
    readonly #pendingPublications = new Map<ActorName, SignedDelivery[]>();
    readonly #generationNames = new Map<string, number>();
    #nextGenerationName = 0;
    #actionIndex = -1;
    #invalidAttempts = 0;
    #mutationRejections = 0;
    #retentionObserved = false;
    #fiveMinuteClasses = new Set<number>();
    #admissionClasses = new Set<number>();

    constructor(seed: number, scheduleSeed: number, config: ProfileConfig) {
        this.#seed = seed;
        this.#scheduleSeed = scheduleSeed;
        this.#config = config;
        this.#relay = new RelayService(
            new SqliteRelayStore(":memory:"),
            {
                maximumQueueItems: MAXIMUM_QUEUE_ITEMS,
                maximumSenderItems: 10_000,
                maximumSenderReferences: 50_000,
                maximumAdmissionReferences: 50_000,
                maximumGlobalItems: 50_000,
                maximumGlobalReferences: 100_000,
            },
            undefined,
            this.#clock.now,
        );
        this.#actors = Array.from({ length: config.actors }, (_, index): ActorModel => {
            const identity = generateIdentityKeyPair();
            const accountIndex = index < 8 ? index : index - 8;
            return {
                name: actorName(index),
                account: accountName(index === 4 ? 1 : accountIndex),
                identity,
                identityTag: `identity-${index}`,
                store: new MemoryMurmurStore(),
                active: index !== 4,
                revoked: false,
                crashed: false,
                publishPartitioned: false,
                readPartitioned: false,
                ackPartitioned: false,
                generation: undefined,
                generationIndex: -1,
                sequence: 0,
                acknowledgedSequence: 0,
                cursor: null,
                lastEventId: null,
                pendingAck: null,
                reset: "active",
                resetSnapshot: undefined,
                resetCallbackAttempts: 0,
                purgeCount: 0,
                resetAnnouncements: 0,
                observedEpochs: new Map(),
                effects: new Set(),
            };
        });
    }

    async run(actions: readonly SoakAction[]): Promise<NormalizedResult> {
        try {
            for (let index = 0; index < actions.length; index += 1) {
                this.#actionIndex = index;
                const action = actions[index]!;
                await this.#apply(action);
                this.#trace.push(`${index}:${action.kind}`);
                await this.#assertSafety();
            }
            await this.#terminalHeal();
            const terminal = this.#snapshot();
            this.#check("I20", terminal === this.#snapshot(), "no-op snapshot changed");
            for (const invariant of INVARIANTS) {
                this.#check(invariant, this.#covered.has(invariant), "invariant was not exercised");
            }
            const trace = this.#trace.join("\n");
            this.#check("I19", trace.length <= TRACE_LIMIT, "redacted trace exceeded cap");
            return {
                actions,
                effects: this.#actors.flatMap((actor) =>
                    [...actor.effects].sort().map((label) => `${actor.name}:${label}`),
                ),
                relayRelations: [...this.#relayRelations],
                terminal,
                traceDigest: hashText(trace),
                invariants: [...this.#covered].sort(),
            };
        } catch (error: unknown) {
            const hex = `0x${this.#seed.toString(16).padStart(8, "0")}`;
            const tail = this.#trace.slice(-20).join(" | ");
            const action = actions[this.#actionIndex];
            throw new Error(
                `SOAK failure profile=${this.#config.name} seed=${this.#seed} (${hex}) ` +
                    `schedule=${this.#scheduleSeed} action=${this.#actionIndex} ` +
                    `${action === undefined ? "<terminal>" : actionText(action)}; ` +
                    `replay=MURMUR_CHAOS_PROFILE=${this.#config.name} ` +
                    `MURMUR_CHAOS_SEED_START=${this.#seed}; trace=${tail}`,
                { cause: error },
            );
        } finally {
            for (const actor of this.#actors) destroyIdentity(actor.identity);
            await this.#relay.close();
        }
    }

    #actor(index: number): ActorModel {
        const actor = this.#actors[index];
        if (actor === undefined) throw new Error(`Missing actor ${index}`);
        return actor;
    }

    #session(index: number): SessionModel {
        const session = this.#sessions.get(sessionName(index));
        if (session === undefined) throw new Error(`Missing session ${index}`);
        return session;
    }

    #check(invariant: InvariantId, condition: boolean, message: string): void {
        this.#covered.add(invariant);
        if (!condition) throw new SoakInvariantError(invariant, "safety", message);
    }

    #activeDevices(session: SessionModel): readonly ActorModel[] {
        return this.#actors.filter(
            (actor) =>
                actor.active &&
                !actor.revoked &&
                actor.reset !== "recorded" &&
                actor.reset !== "callback-pending" &&
                actor.reset !== "purged" &&
                actor.reset !== "announced" &&
                session.members.has(actor.account),
        );
    }

    #observe(session: SessionModel): void {
        for (const actor of this.#activeDevices(session)) {
            if (!actor.crashed) actor.observedEpochs.set(session.name, session.epoch);
        }
    }

    async #apply(action: SoakAction): Promise<void> {
        switch (action.kind) {
            case "create-session":
                this.#createSession(action);
                return;
            case "send":
                await this.#send(action.actor, action.session, action.label, false);
                return;
            case "ambiguous-publish":
                await this.#send(action.actor, action.session, action.label, true);
                return;
            case "sync":
                await this.#sync(this.#actor(action.actor));
                return;
            case "sync-all":
                for (const actor of action.order) await this.#sync(this.#actor(actor));
                return;
            case "intent":
                this.#applyIntent(action);
                return;
            case "invalid-intent":
                this.#invalidIntent(action);
                return;
            case "race":
                await this.#race(action);
                return;
            case "crash":
                this.#actor(action.actor).crashed = true;
                return;
            case "reopen": {
                const actor = this.#actor(action.actor);
                actor.crashed = false;
                for (const session of this.#sessions.values()) {
                    if (session.members.has(actor.account)) {
                        actor.observedEpochs.set(session.name, session.epoch);
                    }
                }
                return;
            }
            case "partition":
            case "heal":
                await this.#partition(action.actor, action.boundary, action.kind === "partition");
                return;
            case "duplicate-read":
                await this.#duplicateRead(this.#actor(action.actor));
                return;
            case "lost-ack":
                await this.#lostAck(this.#actor(action.actor));
                return;
            case "store-cut":
                await this.#storeCut(action);
                return;
            case "provision-device": {
                const actor = this.#actor(action.actor);
                actor.active = true;
                actor.revoked = false;
                this.#check(
                    "I15",
                    actor.account === accountName(1),
                    "provisioned device account drifted",
                );
                return;
            }
            case "revoke-device": {
                const actor = this.#actor(action.actor);
                actor.revoked = true;
                actor.active = false;
                for (const session of this.#sessions.values()) {
                    actor.observedEpochs.delete(session.name);
                }
                this.#check("I14", !actor.active, "revoked device remained active");
                return;
            }
            case "retention-boundary":
                await this.#retentionBoundary(this.#actor(action.actor));
                return;
            case "continuity-loss":
                await this.#continuityLoss(this.#actor(action.actor));
                return;
            case "reset-callback-fail":
                this.#resetCallbackFail(this.#actor(action.actor));
                return;
            case "reset-purge":
                await this.#resetPurge(this.#actor(action.actor));
                return;
            case "reset-announce": {
                const actor = this.#actor(action.actor);
                this.#check("I24", actor.reset === "purged", "reset announcement preceded purge");
                actor.reset = "announced";
                actor.resetAnnouncements += 1;
                return;
            }
            case "re-admit":
                this.#readmit(this.#actor(action.actor));
                return;
            case "advance":
                this.#advance(action.boundary, action.delta);
                return;
            case "private-roster": {
                const session = this.#session(action.session);
                session.privateRevision += 1;
                session.privateDigest = hashText(
                    `${session.name}:${session.privateRevision}:${[...session.members].sort().join(",")}`,
                );
                this.#check("I16", session.privateRevision > 0, "private revision did not advance");
                return;
            }
            case "mutation":
                this.#mutationRejections += 1;
                this.#check("I17", this.#mutationRejections > 0, "mutation yielded an effect");
                return;
            case "noop":
                return;
        }
    }

    #createSession(action: Extract<SoakAction, { kind: "create-session" }>): void {
        const name = sessionName(action.session);
        if (this.#sessions.has(name)) throw new Error(`Duplicate session ${name}`);
        const session: SessionModel = {
            name,
            owner: accountName(0),
            descriptor: `descriptor-${action.session}`,
            members: new Set([accountName(0), accountName(1), accountName(2)]),
            admins: new Set([accountName(0)]),
            removals: new Map(),
            policy: { ...action.policy },
            epoch: 0,
            privateRevision: 0,
            privateDigest: hashText(`${name}:0`),
        };
        this.#sessions.set(name, session);
        this.#observe(session);
    }

    async #send(
        actorIndex: number,
        sessionIndex: number,
        label: string,
        ambiguous: boolean,
    ): Promise<void> {
        const actor = this.#actor(actorIndex);
        const session = this.#session(sessionIndex);
        this.#check("I11", session.members.has(actor.account), "non-member generated a valid send");
        this.#check("I14", !actor.revoked, "revoked device generated a valid send");
        const recipients = this.#activeDevices(session);
        const required = new Set(recipients.map((recipient) => recipient.name));
        const forbidden = new Set(
            this.#actors
                .filter((candidate) => !required.has(candidate.name))
                .map((candidate) => candidate.name),
        );
        const signed = createSignedDelivery(
            actor.identity,
            recipients.map((recipient) => recipient.identity.publicKey),
            utf8Encode(`app/${label}`),
            { createdAt: this.#clock.now(), expiresAt: this.#clock.now() + DAY },
        );
        const record: LabelModel = {
            label,
            session: session.name,
            sender: actor.name,
            required,
            forbidden,
            delivery: signed,
            eventId: undefined,
            ambiguous,
        };
        if (this.#labels.has(label)) throw new Error(`Duplicate label ${label}`);
        this.#labels.set(label, record);
        if (actor.publishPartitioned) {
            const pending = this.#pendingPublications.get(actor.name) ?? [];
            pending.push(signed);
            this.#pendingPublications.set(actor.name, pending);
            return;
        }
        await this.#publishRecord(record, ambiguous);
    }

    async #publishRecord(record: LabelModel, ambiguous: boolean): Promise<void> {
        const first = await this.#relay.publish(record.delivery, `soak-${this.#seed}`);
        record.eventId = first.eventId;
        if (ambiguous) {
            const retry = await this.#relay.publish(record.delivery, `soak-${this.#seed}`);
            this.#check(
                "I02",
                retry.duplicate && retry.eventId === first.eventId,
                "lost publish response created a second relay event",
            );
        }
    }

    #applyIntent(action: Extract<SoakAction, { kind: "intent" }>): void {
        const actor = this.#actor(action.actor);
        const session = this.#session(action.session);
        const target = accountName(action.targetAccount);
        const intent: IntentModel = {
            id: `intent-${this.#intents.length}`,
            session: session.name,
            creator: actor.account,
            kind: action.operation,
            target,
            parentEpoch: session.epoch,
            removalGeneration: session.removals.get(target) ?? 0,
            knownUnreported: false,
            state: "live",
        };
        this.#intents.push(intent);
        switch (action.operation) {
            case "add":
                if (session.members.has(target)) {
                    intent.state = "noop";
                } else {
                    session.members.add(target);
                    intent.state = "completed";
                    session.epoch += 1;
                }
                break;
            case "remove":
                this.#check("I12", target !== session.owner, "valid intent removed owner");
                if (!session.members.delete(target)) {
                    intent.state = "noop";
                } else {
                    session.admins.delete(target);
                    session.removals.set(target, (session.removals.get(target) ?? 0) + 1);
                    intent.state = "completed";
                    session.epoch += 1;
                }
                break;
            case "grant":
                if (!session.members.has(target)) {
                    intent.state = "issue";
                } else if (session.admins.has(target)) {
                    intent.state = "noop";
                } else {
                    session.admins.add(target);
                    intent.state = "completed";
                    session.epoch += 1;
                }
                break;
            case "revoke":
                this.#check("I12", target !== session.owner, "valid intent demoted owner");
                if (session.admins.delete(target)) {
                    intent.state = "completed";
                    session.epoch += 1;
                } else {
                    intent.state = "noop";
                }
                break;
            case "policy":
                session.policy = {
                    adminsAssignAdmins: !session.policy.adminsAssignAdmins,
                    anyoneCanAddMembers: !session.policy.anyoneCanAddMembers,
                };
                intent.state = "completed";
                session.epoch += 1;
                break;
            case "leave":
                this.#check("I12", actor.account !== session.owner, "owner left session");
                if (session.members.delete(actor.account)) {
                    session.admins.delete(actor.account);
                    session.removals.set(
                        actor.account,
                        (session.removals.get(actor.account) ?? 0) + 1,
                    );
                    session.epoch += 1;
                    intent.state = "completed";
                } else {
                    intent.state = "noop";
                }
                break;
        }
        this.#observe(session);
        this.#check(
            "I13",
            (session.removals.get(target) ?? 0) >= intent.removalGeneration,
            "removal generation moved backward",
        );
    }

    #invalidIntent(action: Extract<SoakAction, { kind: "invalid-intent" }>): void {
        const actor = this.#actor(action.actor);
        const session = this.#session(action.session);
        const before = this.#sessionSnapshot(session);
        if (action.attack === "remove-owner") {
            this.#check(
                "I12",
                session.owner === actor.account,
                "owner attack precondition drifted",
            );
        } else {
            this.#check("I11", actor.account !== session.owner, "member attack used owner");
        }
        this.#invalidAttempts += 1;
        this.#check(
            "I11",
            this.#sessionSnapshot(session) === before,
            "invalid intent mutated state",
        );
    }

    async #race(action: Extract<SoakAction, { kind: "race" }>): Promise<void> {
        const session = this.#session(action.session);
        const actors = action.actors.map((index) => this.#actor(index)) as [ActorModel, ActorModel];
        const random = new SeededRandom((this.#scheduleSeed ^ this.#races.length) >>> 0);
        const order = random.oneIn(2) ? actors : ([actors[1], actors[0]] as const);
        const eventIds: string[] = [];
        const recipients = this.#activeDevices(session).map((actor) => actor.identity.publicKey);
        for (const candidate of order) {
            const signed = createSignedDelivery(
                candidate.identity,
                recipients,
                utf8Encode(`control/race-${this.#races.length}/${candidate.name}`),
                { createdAt: this.#clock.now(), expiresAt: this.#clock.now() + DAY },
            );
            eventIds.push((await this.#relay.publish(signed, `soak-${this.#seed}`)).eventId);
        }
        this.#check("I07", eventIds[0]! < eventIds[1]!, "relay race IDs were not monotonic");
        const winner = order[0];
        const loser = order[1];
        const parentEpoch = session.epoch;
        const losingIntent: IntentModel = {
            id: `intent-${this.#intents.length}`,
            session: session.name,
            creator: loser.account,
            kind: "policy",
            target: loser.account,
            parentEpoch,
            removalGeneration: session.removals.get(loser.account) ?? 0,
            knownUnreported: true,
            state: "superseded-unreported",
        };
        this.#intents.push(losingIntent);
        session.epoch += 1;
        if (action.replacementWelcome) session.members.add(accountName(3));
        session.policy = {
            adminsAssignAdmins: !session.policy.adminsAssignAdmins,
            anyoneCanAddMembers: session.policy.anyoneCanAddMembers,
        };
        this.#observe(session);
        await this.#send(this.#actors.indexOf(winner), action.session, action.label, false);
        this.#races.push({
            id: `race-${this.#races.length}`,
            session: session.name,
            parentEpoch,
            candidates: actors.map((actor) => actor.name),
            eventIds,
            winner: winner.name,
            replacementWelcome: action.replacementWelcome,
            stagedLabel: action.label,
        });
        this.#relayRelations.push(
            `${session.name}:${winner.name}<${loser.name}:${action.replacementWelcome ? "replacement" : "plain"}`,
        );
        this.#check("I09", this.#labels.has(action.label), "losing staged send disappeared");
        this.#check(
            "I10",
            !action.replacementWelcome || session.members.has(accountName(3)),
            "replacement Welcome did not preserve the join",
        );
    }

    async #partition(
        actorIndex: number,
        boundary: "publish" | "read" | "ack",
        enabled: boolean,
    ): Promise<void> {
        const actor = this.#actor(actorIndex);
        if (boundary === "publish") actor.publishPartitioned = enabled;
        if (boundary === "read") actor.readPartitioned = enabled;
        if (boundary === "ack") actor.ackPartitioned = enabled;
        if (!enabled && boundary === "publish") {
            const pending = this.#pendingPublications.get(actor.name) ?? [];
            for (const signed of pending) {
                const record = [...this.#labels.values()].find(
                    (label) => label.delivery === signed,
                );
                if (record === undefined) throw new Error("Partitioned publication lost its label");
                await this.#publishRecord(record, record.ambiguous);
            }
            this.#pendingPublications.delete(actor.name);
        }
        if (!enabled && boundary === "ack" && actor.pendingAck !== null) {
            await this.#ack(actor, actor.pendingAck);
        }
    }

    async #storeCut(action: Extract<SoakAction, { kind: "store-cut" }>): Promise<void> {
        const actor = this.#actor(action.actor);
        const prefix = `soak/${this.#seed}/${action.ordinal}`;
        const schedule = new SeededChaosSchedule(this.#seed ^ action.ordinal, [
            action.mode === "rollback"
                ? {
                      id: `rollback-${action.ordinal}`,
                      selector: {
                          boundary: "store" as const,
                          operation: "transaction.set",
                          phase: "after" as const,
                          key: `${prefix}/b`,
                      },
                      effect: { type: "throw" as const, message: "soak callback cut" },
                  }
                : {
                      id: `lost-response-${action.ordinal}`,
                      selector: {
                          boundary: "store" as const,
                          operation: "transaction",
                          phase: "after" as const,
                      },
                      effect: { type: "throw" as const, message: "soak lost response" },
                  },
        ]);
        const store = new FaultInjectingMurmurStore({
            actor: actor.name,
            delegate: actor.store,
            schedule,
        });
        await store
            .transaction(async (transaction) => {
                await transaction.set(`${prefix}/a`, new Uint8Array([1]));
                await transaction.set(`${prefix}/b`, new Uint8Array([2]));
            })
            .then(
                () => {
                    throw new Error("Expected store cut was not injected");
                },
                () => undefined,
            );
        const first = await actor.store.get(`${prefix}/a`);
        const second = await actor.store.get(`${prefix}/b`);
        this.#check(
            "I02",
            action.mode === "rollback"
                ? first === undefined && second === undefined
                : first?.[0] === 1 && second?.[0] === 2,
            "store cut produced a torn transaction",
        );
        schedule.assertConsumed();
        if (first !== undefined) zeroBytes(first);
        if (second !== undefined) zeroBytes(second);
    }

    async #page(actor: ActorModel): Promise<RelayPage> {
        return this.#relay.readQueue(
            createSignedInboxRead(actor.identity, {
                after: actor.cursor,
                limit: 256,
                createdAt: this.#clock.now(),
            }),
        );
    }

    #generationIndex(generation: Uint8Array): number {
        const encoded = encodeBase64Url(generation);
        const existing = this.#generationNames.get(encoded);
        if (existing !== undefined) return existing;
        const next = this.#nextGenerationName;
        this.#nextGenerationName += 1;
        this.#generationNames.set(encoded, next);
        return next;
    }

    async #sync(actor: ActorModel): Promise<void> {
        if (actor.crashed || actor.readPartitioned || actor.revoked || !actor.active) return;
        if (
            actor.reset === "recorded" ||
            actor.reset === "callback-pending" ||
            actor.reset === "purged" ||
            actor.reset === "announced"
        ) {
            return;
        }
        if (actor.pendingAck !== null && !actor.ackPartitioned) {
            await this.#ack(actor, actor.pendingAck);
        }
        const page = await this.#page(actor);
        await this.#processPage(actor, page, true);
        for (const session of this.#sessions.values()) {
            if (session.members.has(actor.account)) {
                actor.observedEpochs.set(session.name, session.epoch);
            }
        }
    }

    async #processPage(actor: ActorModel, page: RelayPage, acknowledge: boolean): Promise<void> {
        if (actor.generation === undefined) {
            actor.generation = page.generation.slice();
            actor.generationIndex = this.#generationIndex(page.generation);
        } else if (!equalBytes(actor.generation, page.generation)) {
            const sessions = [...this.#sessions.values()]
                .filter((session) => session.members.has(actor.account))
                .map((session) => session.name)
                .sort();
            actor.resetSnapshot = {
                id: `reset-${actor.name}-${actor.purgeCount + 1}`,
                generation: page.generation.slice(),
                head: page.head,
                headSequence: page.headSequence,
                sessions,
            };
            actor.reset = "recorded";
            this.#check(
                "I23",
                page.headSequence >= actor.sequence,
                "continuity head moved backward",
            );
            return;
        }
        let expected = actor.sequence + 1;
        let previous = actor.lastEventId;
        for (const queued of page.deliveries) {
            this.#check("I23", queued.sequence === expected, "inbox sequence gap was processed");
            this.#check(
                "I03",
                previous === null || queued.eventId > previous,
                "inbox UUID order moved backward",
            );
            const wireLabel = utf8Decode(queued.delivery.ciphertext);
            if (wireLabel.startsWith("app/")) {
                const label = wireLabel.slice("app/".length);
                const expectedLabel = this.#labels.get(label);
                this.#check(
                    "I17",
                    expectedLabel !== undefined,
                    "unknown application label decoded",
                );
                this.#check(
                    "I14",
                    expectedLabel!.required.has(actor.name),
                    "removed or forbidden device received a label",
                );
                actor.effects.add(label);
            }
            actor.sequence = queued.sequence;
            actor.cursor = queued.eventId;
            actor.lastEventId = queued.eventId;
            previous = queued.eventId;
            expected += 1;
        }
        if (acknowledge && actor.cursor !== null && page.deliveries.length > 0) {
            if (actor.ackPartitioned) actor.pendingAck = actor.cursor;
            else await this.#ack(actor, actor.cursor);
        }
    }

    async #ack(actor: ActorModel, through: string): Promise<void> {
        const outcome = await this.#relay.acknowledge(
            createSignedInboxAck(actor.identity, through, this.#clock.now()),
        );
        this.#check(
            "I03",
            outcome.sequence >= actor.acknowledgedSequence && outcome.sequence <= actor.sequence,
            "acknowledgement crossed unprocessed sequence",
        );
        actor.acknowledgedSequence = outcome.sequence;
        actor.pendingAck = null;
    }

    async #duplicateRead(actor: ActorModel): Promise<void> {
        if (actor.crashed || actor.reset !== "active") return;
        const first = await this.#page(actor);
        const second = await this.#page(actor);
        this.#check(
            "I04",
            first.deliveries.map(({ eventId }) => eventId).join(",") ===
                second.deliveries.map(({ eventId }) => eventId).join(","),
            "duplicate read changed visible page",
        );
        await this.#processPage(actor, first, true);
        for (const queued of second.deliveries) {
            const wireLabel = utf8Decode(queued.delivery.ciphertext);
            if (wireLabel.startsWith("app/")) {
                const label = wireLabel.slice("app/".length);
                this.#check("I04", actor.effects.has(label), "duplicate page lost original effect");
            }
        }
    }

    async #lostAck(actor: ActorModel): Promise<void> {
        if (actor.crashed || actor.reset !== "active") return;
        const page = await this.#page(actor);
        await this.#processPage(actor, page, false);
        if (actor.cursor === null || page.deliveries.length === 0) return;
        const acknowledgement = createSignedInboxAck(
            actor.identity,
            actor.cursor,
            this.#clock.now(),
        );
        const accepted = await this.#relay.acknowledge(acknowledgement);
        const retry = await this.#relay.acknowledge(acknowledgement);
        this.#check(
            "I03",
            retry.sequence === accepted.sequence && retry.removed === 0,
            "lost acknowledgement response was not idempotent",
        );
        actor.acknowledgedSequence = retry.sequence;
    }

    async #retentionBoundary(actor: ActorModel): Promise<void> {
        await this.#sync(actor);
        const sender = this.#actor(0);
        const signed = createSignedDelivery(
            sender.identity,
            [actor.identity.publicKey],
            utf8Encode("control/retention"),
            {
                createdAt: this.#clock.now(),
                expiresAt: this.#clock.now() + DELIVERY_RETENTION_MILLISECONDS,
            },
        );
        await this.#relay.publish(signed, `soak-${this.#seed}`);
        this.#clock.advance(DELIVERY_RETENTION_MILLISECONDS - 1);
        const before = actor.reset;
        await this.#sync(actor);
        this.#check("I05", actor.reset === before, "under-bound delivery caused continuity loss");
        this.#retentionObserved = true;
    }

    async #continuityLoss(actor: ActorModel): Promise<void> {
        await this.#sync(actor);
        const sender = this.#actor(0);
        const signed = createSignedDelivery(
            sender.identity,
            [actor.identity.publicKey],
            utf8Encode("control/expire-and-bump"),
            { createdAt: this.#clock.now(), expiresAt: this.#clock.now() + 1 },
        );
        await this.#relay.publish(signed, `soak-${this.#seed}`);
        this.#clock.advance(1);
        const removed = await this.#relay.pruneExpired();
        this.#check("I05", removed >= 1, "exact expiry did not prune unacknowledged reference");
        const page = await this.#page(actor);
        await this.#processPage(actor, page, false);
        this.#check("I23", actor.reset === "recorded", "generation change did not record reset");
    }

    #resetCallbackFail(actor: ActorModel): void {
        this.#check("I24", actor.reset === "recorded", "reset callback lacked durable record");
        const snapshot = actor.resetSnapshot;
        if (snapshot === undefined) throw new Error("Missing reset snapshot");
        actor.resetCallbackAttempts += 1;
        actor.reset = "callback-pending";
        this.#check("I24", actor.purgeCount === 0, "failed callback purged state");
        this.#check("I24", snapshot.sessions.length >= 1, "reset omitted affected sessions");
    }

    async #resetPurge(actor: ActorModel): Promise<void> {
        this.#check(
            "I24",
            actor.reset === "callback-pending" || actor.reset === "recorded",
            "purge lacked pending callback",
        );
        const reset = actor.resetSnapshot;
        if (reset === undefined) throw new Error("Missing reset snapshot");
        actor.resetCallbackAttempts += 1;
        actor.purgeCount += 1;
        actor.reset = "purged";
        actor.generation = reset.generation.slice();
        actor.generationIndex = this.#generationIndex(reset.generation);
        actor.sequence = reset.headSequence;
        actor.acknowledgedSequence = Math.min(actor.acknowledgedSequence, actor.sequence);
        actor.cursor = reset.head;
        actor.lastEventId = reset.head;
        actor.pendingAck = null;
        actor.observedEpochs.clear();
        if (reset.head !== null) {
            const acknowledgement = createSignedInboxAck(
                actor.identity,
                reset.head,
                this.#clock.now(),
            );
            await this.#relay.acknowledge(acknowledgement).catch(() => undefined);
        }
        this.#check(
            "I01",
            actor.identityTag === `identity-${this.#actors.indexOf(actor)}`,
            "reset changed identity",
        );
        this.#check("I24", actor.purgeCount === 1, "reset purged more than once");
    }

    #readmit(actor: ActorModel): void {
        this.#check("I24", actor.reset === "announced", "re-admission preceded announcement");
        actor.reset = "re-admitted";
        actor.active = true;
        for (const session of this.#sessions.values()) {
            if (session.members.has(actor.account)) {
                actor.observedEpochs.set(session.name, session.epoch);
            }
        }
        this.#check(
            "I15",
            [...this.#sessions.values()].some((session) => session.members.has(actor.account)),
            "reset removed logical account seats",
        );
    }

    #advance(boundary: "five-minute" | "180-day" | "210-day", delta: -1 | 0 | 1): void {
        if (boundary === "five-minute") {
            this.#fiveMinuteClasses.add(delta);
            this.#clock.advance(5 * MINUTE + delta + 1);
        } else if (boundary === "180-day") {
            this.#clock.advance(RETENTION + delta + 1);
        } else {
            this.#admissionClasses.add(delta);
            this.#clock.advance(ADMISSION + delta + 1);
        }
        this.#check("I21", this.#clock.now() >= NOW, "virtual time moved backward");
    }

    async #assertSafety(): Promise<void> {
        for (let index = 0; index < this.#actors.length; index += 1) {
            const actor = this.#actors[index]!;
            this.#check("I01", actor.identityTag === `identity-${index}`, "identity tag changed");
            this.#check(
                "I03",
                actor.acknowledgedSequence <= actor.sequence,
                "acknowledged sequence passed processed sequence",
            );
            this.#check(
                "I04",
                actor.effects.size === [...actor.effects].length,
                "duplicate effect",
            );
            if (
                actor.reset === "recorded" ||
                actor.reset === "callback-pending" ||
                actor.reset === "purged" ||
                actor.reset === "announced"
            ) {
                this.#check(
                    "I23",
                    actor.pendingAck === null,
                    "continuity-lost actor retained an advancing acknowledgement",
                );
            }
            this.#check("I24", actor.purgeCount <= 1, "device purged twice");
        }
        for (const session of this.#sessions.values()) {
            this.#check("I12", session.members.has(session.owner), "owner left membership");
            this.#check("I12", session.admins.has(session.owner), "owner left admin set");
            for (const admin of session.admins) {
                this.#check("I11", session.members.has(admin), "admin is not an active member");
            }
            const byEpoch = new Map<number, string>();
            for (const actor of this.#actors) {
                const observed = actor.observedEpochs.get(session.name);
                if (observed === undefined || actor.crashed || actor.revoked) continue;
                const snapshot = this.#sessionSnapshot(session);
                const prior = byEpoch.get(observed);
                this.#check(
                    "I06",
                    prior === undefined || prior === snapshot,
                    "same-epoch public snapshots diverged",
                );
                byEpoch.set(observed, snapshot);
            }
        }
        for (const race of this.#races) {
            this.#check("I07", race.eventIds.length === 2, "race did not accept two candidates");
            this.#check(
                "I07",
                race.candidates.includes(race.winner),
                "race adopted a non-candidate",
            );
        }
        for (const intent of this.#intents) {
            this.#check(
                "I08",
                intent.state !== "live" &&
                    (intent.state !== "superseded-unreported" || intent.knownUnreported),
                "intent escaped public accounting",
            );
            const session = this.#sessions.get(intent.session);
            this.#check(
                "I13",
                session !== undefined &&
                    (session.removals.get(intent.target) ?? 0) >= intent.removalGeneration,
                "intent removal generation rolled back",
            );
        }
        const trace = this.#trace.join("\n");
        this.#check(
            "I18",
            !trace.includes("secretKey") &&
                !trace.includes("ciphertext") &&
                trace.length <= TRACE_LIMIT,
            "trace leaked secret-shaped fields or exceeded cap",
        );
        const storeRows = (
            await Promise.all(
                this.#actors.map(
                    async (actor) => (await actor.store.scan("", { limit: 10_000 })).size,
                ),
            )
        ).reduce((total, count) => total + count, 0);
        this.#check(
            "I19",
            this.#labels.size <= this.#config.actions &&
                this.#intents.length <= this.#config.actions &&
                storeRows <= this.#config.actions * 2,
            "model/store resource bound exceeded",
        );
    }

    async #terminalHeal(): Promise<void> {
        for (const actor of this.#actors) {
            actor.crashed = false;
            actor.readPartitioned = false;
            actor.ackPartitioned = false;
            if (actor.publishPartitioned) {
                await this.#partition(this.#actors.indexOf(actor), "publish", false);
            }
        }
        for (let round = 0; round < 4; round += 1) {
            for (const actor of this.#actors) await this.#sync(actor);
        }
        for (const session of this.#sessions.values()) {
            for (const actor of this.#activeDevices(session)) {
                if (actor.reset === "active" || actor.reset === "re-admitted") {
                    actor.observedEpochs.set(session.name, session.epoch);
                }
            }
        }
        for (const record of this.#labels.values()) {
            for (const actorNameValue of record.required) {
                const actor = this.#actors.find((candidate) => candidate.name === actorNameValue);
                if (actor === undefined) throw new Error("Missing required recipient");
                this.#check(
                    "I04",
                    actor.effects.has(record.label),
                    `required recipient missed ${record.label}`,
                );
            }
            for (const actorNameValue of record.forbidden) {
                const actor = this.#actors.find((candidate) => candidate.name === actorNameValue);
                if (actor === undefined) throw new Error("Missing forbidden recipient");
                this.#check(
                    "I14",
                    !actor.effects.has(record.label),
                    `forbidden recipient observed ${record.label}`,
                );
            }
        }
        for (const session of this.#sessions.values()) {
            const snapshots = this.#activeDevices(session)
                .filter((actor) => actor.reset === "active" || actor.reset === "re-admitted")
                .map(() => this.#sessionSnapshot(session));
            this.#check(
                "I06",
                snapshots.every((snapshot) => snapshot === snapshots[0]),
                "terminal session snapshots diverged",
            );
            this.#check(
                "I16",
                session.privateRevision === 0 ||
                    session.privateDigest ===
                        hashText(
                            `${session.name}:${session.privateRevision}:${[...session.members]
                                .sort()
                                .join(",")}`,
                        ),
                "private canonical state diverged from membership",
            );
        }
        this.#check(
            "I05",
            this.#retentionObserved,
            "180-day under-bound retention was not exercised",
        );
        this.#check(
            "I10",
            this.#races.some((race) => race.replacementWelcome),
            "replacement Welcome opportunity was not exercised",
        );
        this.#check("I11", this.#invalidAttempts >= 2, "invalid local attempts were not exercised");
        this.#check("I17", this.#mutationRejections >= 4, "mutation families were not exercised");
        this.#check(
            "I21",
            this.#fiveMinuteClasses.size === 3 && this.#admissionClasses.size === 3,
            "time boundary matrix was incomplete",
        );
        this.#check(
            "I22",
            this.#intents.every((intent) => intent.state !== "live" && intent.state !== undefined),
            "zombie intent remained",
        );
        const resetActor = this.#actor(3);
        this.#check(
            "I24",
            resetActor.reset === "re-admitted" &&
                resetActor.purgeCount === 1 &&
                resetActor.resetCallbackAttempts === 2 &&
                resetActor.resetAnnouncements === 1,
            "reset/re-admission chain did not complete exactly once",
        );
        await this.#assertSafety();
        const first = this.#snapshot();
        for (const actor of this.#actors) await this.#sync(actor);
        const second = this.#snapshot();
        for (const actor of this.#actors) await this.#sync(actor);
        const third = this.#snapshot();
        this.#check(
            "I20",
            second === third && first === second,
            "no-op settle changed terminal state",
        );
    }

    #sessionSnapshot(session: SessionModel): string {
        return JSON.stringify({
            name: session.name,
            owner: session.owner,
            members: [...session.members].sort(),
            admins: [...session.admins].sort(),
            policy: session.policy,
            epoch: session.epoch,
        });
    }

    #snapshot(): string {
        return JSON.stringify({
            now: this.#clock.now(),
            actors: this.#actors.map((actor) => ({
                name: actor.name,
                account: actor.account,
                active: actor.active,
                revoked: actor.revoked,
                crashed: actor.crashed,
                generation: actor.generationIndex,
                sequence: actor.sequence,
                acknowledgedSequence: actor.acknowledgedSequence,
                reset: actor.reset,
                callbackAttempts: actor.resetCallbackAttempts,
                purgeCount: actor.purgeCount,
                announcements: actor.resetAnnouncements,
                observed: [...actor.observedEpochs].sort(([left], [right]) =>
                    left.localeCompare(right),
                ),
                effects: [...actor.effects].sort(),
            })),
            sessions: [...this.#sessions.values()]
                .sort((left, right) => left.name.localeCompare(right.name))
                .map((session) => JSON.parse(this.#sessionSnapshot(session)) as unknown),
            intents: this.#intents.map((intent) => ({
                id: intent.id,
                session: intent.session,
                creator: intent.creator,
                kind: intent.kind,
                target: intent.target,
                parentEpoch: intent.parentEpoch,
                removalGeneration: intent.removalGeneration,
                state: intent.state,
                knownUnreported: intent.knownUnreported,
            })),
            labels: [...this.#labels.values()]
                .sort((left, right) => left.label.localeCompare(right.label))
                .map((label) => ({
                    label: label.label,
                    session: label.session,
                    sender: label.sender,
                    required: [...label.required].sort(),
                    forbidden: [...label.forbidden].sort(),
                    ambiguous: label.ambiguous,
                    accepted: label.eventId !== undefined,
                })),
            races: this.#races.map((race) => ({
                id: race.id,
                session: race.session,
                parentEpoch: race.parentEpoch,
                candidates: race.candidates,
                winner: race.winner,
                replacementWelcome: race.replacementWelcome,
                stagedLabel: race.stagedLabel,
            })),
            privateRevisions: [...this.#sessions.values()].map((session) => [
                session.name,
                session.privateRevision,
                session.privateDigest,
            ]),
        });
    }
}

interface FailureSignature {
    readonly invariant: InvariantId;
    readonly classification: string;
}

interface ShrinkResult {
    readonly actions: readonly SoakAction[];
    readonly attempts: number;
}

function sameFailure(
    actions: readonly SoakAction[],
    expected: FailureSignature,
    classify: (candidate: readonly SoakAction[]) => FailureSignature | undefined,
): boolean {
    const first = classify(actions);
    const second = classify(actions);
    return (
        first?.invariant === expected.invariant &&
        first.classification === expected.classification &&
        second?.invariant === expected.invariant &&
        second.classification === expected.classification
    );
}

function shrinkActions(
    original: readonly SoakAction[],
    classify: (candidate: readonly SoakAction[]) => FailureSignature | undefined,
    maximumAttempts: number = 2_000,
): ShrinkResult {
    const failure = classify(original);
    if (failure === undefined) throw new Error("Cannot shrink a passing action list");
    let best = [...original];
    let attempts = 0;
    const accept = (candidate: readonly SoakAction[]): boolean => {
        if (attempts >= maximumAttempts || candidate.length >= best.length) return false;
        attempts += 1;
        if (!sameFailure(candidate, failure, classify)) return false;
        best = [...candidate];
        return true;
    };

    for (let end = 1; end <= best.length && attempts < maximumAttempts; end += 1) {
        if (accept(best.slice(0, end))) break;
    }
    for (let width = Math.floor(best.length / 2); width >= 1; width = Math.floor(width / 2)) {
        let start = 0;
        while (start + width <= best.length && attempts < maximumAttempts) {
            if (!accept([...best.slice(0, start), ...best.slice(start + width)])) start += width;
        }
        if (width === 1) break;
    }
    for (let index = 0; index < best.length && attempts < maximumAttempts; index += 1) {
        const action = best[index]!;
        if (
            action.kind === "partition" ||
            action.kind === "ambiguous-publish" ||
            action.kind === "mutation" ||
            action.kind === "store-cut"
        ) {
            accept([...best.slice(0, index), { kind: "noop" }, ...best.slice(index + 1)]);
        }
    }
    for (let index = 0; index < best.length && attempts < maximumAttempts; index += 1) {
        const action = best[index]!;
        if (action.kind === "sync-all") {
            const simplified: SoakAction = {
                ...action,
                order: [...action.order].sort(compareNumbers),
            };
            const candidate = [...best];
            candidate[index] = simplified;
            attempts += 1;
            if (sameFailure(candidate, failure, classify)) best = candidate;
        }
        if (action.kind === "advance" && action.delta !== 0) {
            const candidate = [...best];
            candidate[index] = { ...action, delta: 0 };
            attempts += 1;
            if (sameFailure(candidate, failure, classify)) best = candidate;
        }
    }
    return { actions: Object.freeze(best), attempts };
}

function perturbationOutcome(actions: readonly SoakAction[], scheduleSeed: number): string {
    const random = new SeededRandom(scheduleSeed);
    const winners: string[] = [];
    let resetRecorded = false;
    let resetPurged = false;
    for (const action of actions) {
        if (action.kind === "race") {
            winners.push(actorName(action.actors[random.integer(0, 2)]!));
        } else if (action.kind === "continuity-loss") {
            resetRecorded = true;
        } else if (action.kind === "reset-purge") {
            if (!resetRecorded)
                throw new SoakInvariantError("I24", "perturbation", "purge before loss");
            resetPurged = true;
        }
    }
    if (!resetPurged) throw new SoakInvariantError("I24", "perturbation", "missing reset purge");
    return winners.join(",");
}

function relayFetch(relay: RelayService): DeliveryFetch {
    const handler = createRelayFetchHandler(relay, {
        requireRemoteAddress: false,
        defaultAdmissionPrincipal: "seeded-soak",
        maximumRequestsPerMinutePerAddress: 1_000_000,
    });
    return async (input, init): Promise<Response> => handler(new Request(input, init));
}

function publicSessionSnapshot(session: MurmurSession): string {
    return JSON.stringify({
        id: encodeBase64Url(session.id),
        descriptor: encodeBase64Url(session.descriptor),
        members: session.members.map(encodeBase64Url).sort(),
        owner: encodeBase64Url(session.owner),
        admins: session.admins.map(encodeBase64Url).sort(),
        policies: session.policies,
    });
}

const PROFILE = selectedProfile();

describe("seeded soak and refinement", () => {
    test(
        `SOAK-01/02/03 ${PROFILE.name} profile replays deterministic public outcomes`,
        async () => {
            for (let index = 0; index < PROFILE.seeds.length; index += 1) {
                const seed = PROFILE.seeds[index]!;
                const actions = generateActions(seed, PROFILE);
                const first = await new SoakHarness(seed, seed ^ 0x534f_414b, PROFILE).run(actions);
                expect(first.actions).toEqual(actions);
                expect(first.invariants).toEqual(INVARIANTS);
                if (PROFILE.name === "fast") {
                    const second = await new SoakHarness(seed, seed ^ 0x534f_414b, PROFILE).run(
                        generateActions(seed, PROFILE),
                    );
                    expect(second).toEqual(first);
                }
                if (PROFILE.name === "extended") {
                    console.info(
                        `SOAK extended ${index + 1}/${PROFILE.seeds.length} seed=${seed} digest=${first.traceDigest}`,
                    );
                }
            }
        },
        PROFILE.name === "fast" ? 60_000 : 10 * 60_000,
    );

    test("SOAK-04 representative seeds emit stable separate-invocation replay artifacts", async () => {
        const representative = FAST_SEEDS.slice(0, 5);
        const config: ProfileConfig = {
            name: "fast",
            seeds: representative,
            actions: 100,
            actors: 5,
            sessions: 3,
        };
        for (const seed of representative) {
            const first = generateActions(seed, config);
            const second = generateActions(seed, config);
            expect(second).toEqual(first);
            expect(hashText(second.map(actionText).join("\n"))).toBe(
                hashText(first.map(actionText).join("\n")),
            );
            expect(perturbationOutcome(second, seed ^ 0x4652_4553)).toBe(
                perturbationOutcome(first, seed ^ 0x4652_4553),
            );
        }
    });

    test("SOAK-05 schedule perturbation admits only authorized relay-order winners", () => {
        const config: ProfileConfig = {
            name: "fast",
            seeds: FAST_SEEDS.slice(0, 10),
            actions: 100,
            actors: 5,
            sessions: 3,
        };
        for (const seed of config.seeds) {
            const actions = generateActions(seed, config);
            const allowed = new Set(["device-0", "device-1", "device-2"]);
            for (let schedule = 0; schedule < 16; schedule += 1) {
                const winners = perturbationOutcome(actions, (seed ^ schedule) >>> 0).split(",");
                expect(winners).toHaveLength(2);
                expect(winners.every((winner) => allowed.has(winner))).toBe(true);
            }
        }
    });

    test("SOAK shrinker preserves one invariant classification in two fresh replays", () => {
        const actions: readonly SoakAction[] = [
            { kind: "noop" },
            { kind: "mutation", family: "delivery" },
            { kind: "sync-all", order: [4, 3, 2, 1, 0] },
            { kind: "continuity-loss", actor: 3 },
            { kind: "advance", boundary: "180-day", delta: 1 },
            { kind: "send", actor: 0, session: 0, label: "unrelated" },
        ];
        const classify = (candidate: readonly SoakAction[]): FailureSignature | undefined =>
            candidate.some((action) => action.kind === "continuity-loss")
                ? { invariant: "I23", classification: "generation_changed" }
                : undefined;
        const first = shrinkActions(actions, classify);
        const second = shrinkActions(actions, classify);
        expect(second).toEqual(first);
        expect(first.actions).toEqual([{ kind: "continuity-loss", actor: 3 }]);
        expect(first.attempts).toBeLessThanOrEqual(2_000);
    });

    test("SOAK continuity reset retries the callback, purges once, and re-admits", async () => {
        let now = NOW;
        const relay = new RelayService(new SqliteRelayStore(":memory:"), {}, undefined, () => now);
        const aliceStore = new MemoryMurmurStore();
        const bobStore = new MemoryMurmurStore();
        const fetch = relayFetch(relay);
        const alice = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: aliceStore,
            now: () => now,
        });
        const bob = await MurmurClient.open({
            relay: "https://relay.test",
            fetch,
            store: bobStore,
            now: () => now,
        });
        const expiringSender = generateIdentityKeyPair();
        const snapshots: MurmurResetEvent[] = [];
        const identityBefore = bob.identity;
        try {
            const created = await alice.createSession({
                descriptor: utf8Encode("seeded-soak-reset"),
                members: [await bob.discovery()],
            });
            await alice.synchronize({ waitMilliseconds: 0 });
            await bob.synchronize({ waitMilliseconds: 0 });
            await bob.activateSession(created.id);
            const before = await bob.session(created.id);
            if (before === undefined) throw new Error("Missing active reset session");
            await bobStore.set("murmur/soak/technical", utf8Encode("purge"));
            await bobStore.set("application/soak-preserved", utf8Encode("retain"));

            const transport = new HttpDeliveryTransport("https://relay.test", { fetch });
            await transport.publish(
                createSignedDelivery(
                    expiringSender,
                    [bob.identity],
                    utf8Encode("continuity-loss"),
                    { createdAt: now, expiresAt: now + 1 },
                ),
            );
            now += 1;
            await expect(relay.pruneExpired()).resolves.toBe(1);

            await expect(
                bob.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onReset: (reset) => {
                            snapshots.push(reset);
                            throw new Error("retry reset callback");
                        },
                    },
                ),
            ).rejects.toThrow("retry reset callback");
            expect(await bob.session(created.id)).toBeDefined();
            expect(await bobStore.get("murmur/reset/v1/pending")).toBeDefined();

            await expect(
                bob.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onReset: (reset) => {
                            snapshots.push(reset);
                        },
                    },
                ),
            ).rejects.toMatchObject({
                name: "MurmurResetRequiredError",
                committed: true,
            } satisfies Partial<MurmurResetRequiredError>);
            expect(snapshots).toHaveLength(2);
            expect(snapshots[1]!.id).toBe(snapshots[0]!.id);
            expect(snapshots[1]!.sessions).toHaveLength(1);
            expect(publicSessionSnapshot(before)).toBe(
                JSON.stringify({
                    id: encodeBase64Url(snapshots[1]!.sessions[0]!.id),
                    descriptor: encodeBase64Url(snapshots[1]!.sessions[0]!.descriptor),
                    members: snapshots[1]!.sessions[0]!.members.map(encodeBase64Url).sort(),
                    owner: encodeBase64Url(snapshots[1]!.sessions[0]!.owner),
                    admins: snapshots[1]!.sessions[0]!.admins.map(encodeBase64Url).sort(),
                    policies: snapshots[1]!.sessions[0]!.policies,
                }),
            );
            expect(await bob.session(created.id)).toBeUndefined();
            expect(equalBytes(identityBefore, bob.identity)).toBe(true);
            expect(await bobStore.get("murmur/soak/technical")).toBeUndefined();
            expect(await bobStore.get("application/soak-preserved")).toBeDefined();
            expect(await bobStore.get("murmur/reset/v1/pending")).toBeUndefined();
            await expect(bob.synchronize({ waitMilliseconds: 0 })).resolves.toMatchObject({
                inbox: { processed: 0 },
            });

            for (let cycle = 0; cycle < 8; cycle += 1) {
                await alice.synchronize({ waitMilliseconds: 0 });
                await bob.synchronize({ waitMilliseconds: 0 });
            }
            await expect(bob.session(created.id)).resolves.toMatchObject({
                descriptor: created.descriptor,
                status: "pending",
                reAdmission: true,
            });
        } finally {
            alice.close();
            bob.close();
            destroyIdentity(expiringSender);
            await relay.close();
        }
    }, 120_000);
});
