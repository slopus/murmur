import type {
    DeviceRoster,
    DeviceRosterMutation,
    DirectoryClaim,
    DirectoryPrekeyUpload,
    SignedDelivery,
} from "../protocol/index.js";
import type { DirectoryTicketClaims } from "../directory/index.js";
import type { RelaySessionState } from "./sessionState.js";

/** Maximum expired delivery records removed by one writer transaction. */
export const RELAY_EXPIRATION_BATCH_ITEMS = 100;

/** Atomic publication result for one sender-scoped delivery ID. */
export interface PublishOutcome {
    readonly eventId: string;
    readonly duplicate: boolean;
}

/** Store-internal publication result carrying the exact fanout used for wakeups. */
export interface RelayStorePublishOutcome extends PublishOutcome {
    /** Exact relay-derived or direct device fanout. */
    readonly recipients: readonly Uint8Array[];
}

/** Result of one monotonic queue-prefix acknowledgement. */
export interface AcknowledgeOutcome {
    readonly removed: number;
    readonly generation: Uint8Array;
    readonly sequence: number;
}

/** Per-identity queue bounds enforced atomically across a multicast. */
export interface QueueLimits {
    readonly maximumRecipients: number;
    readonly maximumItems: number;
    readonly maximumBytes: number;
    readonly maximumSenderItems: number;
    readonly maximumSenderBytes: number;
    readonly maximumSenderReferences: number;
    readonly maximumAdmissionReferences: number;
    readonly maximumGlobalItems: number;
    readonly maximumGlobalBytes: number;
    readonly maximumGlobalReferences: number;
}

/** Allocation bound applied while materializing one queue page. */
export interface PageReadConstraints {
    readonly maximumEncodedBytes: number;
}

/** One retained queue reference and its shared delivery. */
export interface QueuedDelivery {
    readonly eventId: string;
    readonly sequence: number;
    readonly delivery: SignedDelivery;
}

/** One authenticated recipient queue page. */
export interface QueuePage {
    readonly deliveries: readonly QueuedDelivery[];
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: Uint8Array;
    readonly exhausted: boolean;
}

/** Atomic persistence operations required by the identity-queue relay. */
export interface RelayStore {
    publish(
        delivery: SignedDelivery,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<RelayStorePublishOutcome>;
    /** Replay-protected removal of every pending delivery owned by one session. */
    deleteSessionDeliveries(
        ownerAccount: Uint8Array,
        sessionId: Uint8Array,
        requestId: string,
        now: number,
    ): Promise<number>;
    /** Replay-protected terminal removal of every row owned by one account. */
    deleteAccountState(accountKey: Uint8Array, requestId: string, now: number): Promise<void>;
    /** Resolve the unique current account that owns one active device key. */
    readDeviceAccount(deviceKey: Uint8Array): Promise<Uint8Array | undefined>;
    /** Read relay-held membership and role state for one exact session. */
    readSessionState(sessionId: Uint8Array): Promise<RelaySessionState | undefined>;
    /** Read one current roster by exact public account identity key. */
    readDeviceRoster(accountKey: Uint8Array): Promise<DeviceRoster | undefined>;
    /** Record successful session-token issuance without advancing the roster revision. */
    recordDeviceAccess(deviceKey: Uint8Array, accessedAt: number): Promise<boolean>;
    /** Atomically apply and notify one replay-protected identity-signed roster mutation. */
    mutateDeviceRoster(
        delivery: SignedDelivery,
        mutation: DeviceRosterMutation,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<DeviceRoster>;
    /** Replace or replenish one active device's account-signed directory state. */
    uploadDirectoryPrekeys(
        delivery: SignedDelivery,
        upload: DirectoryPrekeyUpload,
        now: number,
    ): Promise<void>;
    /** Spend one ticket use and atomically claim one prekey per active device. */
    claimDirectory(
        accountKey: Uint8Array,
        ticket: DirectoryTicketClaims,
        now: number,
        limits: QueueLimits,
        admissionPrincipal: Uint8Array,
    ): Promise<DirectoryClaim>;
    readQueue(
        recipient: Uint8Array,
        after: string | null,
        limit: number,
        now: number,
        constraints: PageReadConstraints,
    ): Promise<QueuePage>;
    acknowledge(recipient: Uint8Array, through: string, now: number): Promise<AcknowledgeOutcome>;
    /** Invalidate every known inbox after an operator-declared state restoration. */
    declareRestored(): Promise<number>;
    pruneExpired(now: number): Promise<number>;
    health(): Promise<void>;
    close(): Promise<void>;
}
