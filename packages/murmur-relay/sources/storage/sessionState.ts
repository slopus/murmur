import { RelayError, type DeliverySessionControl } from "../protocol/index.js";
import { encodeBase64Url } from "../utils/base64Url.js";
import { equalBytes } from "../utils/bytes.js";

/** Relay-held routing and basic role state for one MLS session epoch. */
export interface RelaySessionState {
    readonly sessionId: Uint8Array;
    readonly epoch: bigint;
    readonly ownerAccount: Uint8Array;
    readonly members: readonly Uint8Array[];
    /** Roster revision incorporated by the accepted MLS epoch for each member account. */
    readonly rosterRevisions: readonly {
        readonly accountKey: Uint8Array;
        readonly revision: number;
    }[];
    /** Canonically sorted admins excluding the owner. */
    readonly admins: readonly Uint8Array[];
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
    readonly sendPolicy: "everyone" | "admins";
}

/** Atomic session-state decision made before queue fanout. */
export interface ResolvedSessionPublication {
    readonly nextState: RelaySessionState;
    readonly stateChanged: boolean;
    readonly fanoutAccounts: readonly Uint8Array[];
    readonly coverageAccounts: readonly Uint8Array[];
}

function accountMap(accounts: readonly Uint8Array[]): Map<string, Uint8Array> {
    return new Map(accounts.map((account) => [encodeBase64Url(account), account]));
}

function sortedAccounts(accounts: Iterable<Uint8Array>): readonly Uint8Array[] {
    return [...accountMap([...accounts]).entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([, account]) => account);
}

function isAdmin(state: RelaySessionState, account: Uint8Array): boolean {
    return (
        equalBytes(state.ownerAccount, account) ||
        state.admins.some((admin) => equalBytes(admin, account))
    );
}

function unauthorized(message: string): never {
    throw new RelayError(403, message, { error: "session_unauthorized" });
}

function validateRoleState(
    members: Map<string, Uint8Array>,
    owner: Uint8Array,
    admins: readonly Uint8Array[],
): void {
    if (!members.has(encodeBase64Url(owner))) unauthorized("Session owner is not a member");
    if (admins.some((admin) => !members.has(encodeBase64Url(admin)))) {
        unauthorized("Session admin is not a member");
    }
}

/**
 * Validate relay-visible session control against the current state and derive the next state.
 *
 * Device-to-account roster checks and exact device fanout are store-specific and run after this
 * policy decision in the same transaction.
 */
export function resolveSessionPublication(
    sessionId: Uint8Array,
    ownerAccount: Uint8Array,
    senderAccount: Uint8Array,
    control: DeliverySessionControl,
    current: RelaySessionState | undefined,
): ResolvedSessionPublication {
    if (control.type === "create") {
        if (current !== undefined) {
            throw new RelayError(409, "Session already exists", { error: "session_exists" });
        }
        if (
            control.epoch !== 0n ||
            !equalBytes(control.roles.owner, ownerAccount) ||
            !equalBytes(control.roles.owner, senderAccount)
        ) {
            unauthorized("Invalid session creation owner or epoch");
        }
        const members = accountMap(control.members);
        validateRoleState(members, control.roles.owner, control.roles.admins);
        const nextState: RelaySessionState = {
            sessionId,
            epoch: 1n,
            ownerAccount: control.roles.owner,
            members: control.members,
            rosterRevisions: [],
            admins: control.roles.admins,
            adminsAssignAdmins: control.roles.adminsAssignAdmins,
            anyoneCanAddMembers: control.roles.anyoneCanAddMembers,
            sendPolicy: control.roles.sendPolicy,
        };
        return {
            nextState,
            stateChanged: true,
            fanoutAccounts: control.members,
            coverageAccounts: control.members,
        };
    }

    if (current === undefined) {
        throw new RelayError(409, "Unknown relay session", { error: "unknown_session" });
    }
    if (!equalBytes(current.ownerAccount, ownerAccount)) {
        unauthorized("Session owner tag does not match relay state");
    }
    const currentMembers = accountMap(current.members);
    if (!currentMembers.has(encodeBase64Url(senderAccount))) {
        unauthorized("Session sender is not a current member");
    }
    const priorEpochMessage =
        control.type === "message" && current.epoch > 0n && control.epoch === current.epoch - 1n;
    if (control.epoch !== current.epoch && !priorEpochMessage) {
        throw new RelayError(409, "Session publication extends a stale epoch", {
            error: "stale_session_epoch",
            epoch: current.epoch.toString(),
        });
    }
    if (control.type === "message") {
        if (
            control.content === "application" &&
            current.sendPolicy === "admins" &&
            !isAdmin(current, senderAccount)
        ) {
            unauthorized("Session send policy rejects this sender");
        }
        return {
            nextState: current,
            stateChanged: false,
            fanoutAccounts: current.members,
            // A message already encrypted before a concurrent Commit may arrive just after it.
            // Current-epoch sends still prove complete device coverage; the bounded prior-epoch
            // race cannot be re-encrypted for accounts added by the winning Commit.
            coverageAccounts: priorEpochMessage ? [] : current.members,
        };
    }

    if (!equalBytes(control.roles.owner, current.ownerAccount)) {
        unauthorized("A Commit cannot change the session owner");
    }
    const nextMembers = accountMap(control.members);
    validateRoleState(nextMembers, control.roles.owner, control.roles.admins);
    const addedAccounts = [...nextMembers].filter(([account]) => !currentMembers.has(account));
    const removedAccounts = [...currentMembers].filter(([account]) => !nextMembers.has(account));
    const changedAccounts = new Set(
        control.changes.map((change) => encodeBase64Url(change.accountKey)),
    );
    if (
        addedAccounts.some(([account]) => !changedAccounts.has(account)) ||
        removedAccounts.some(([account]) => !changedAccounts.has(account)) ||
        control.changes.some((change) =>
            change.type === "add"
                ? !nextMembers.has(encodeBase64Url(change.accountKey))
                : !currentMembers.has(encodeBase64Url(change.accountKey)),
        )
    ) {
        unauthorized("Session Commit summary does not explain its membership state");
    }
    if (
        addedAccounts.length > 0 &&
        !isAdmin(current, senderAccount) &&
        !current.anyoneCanAddMembers
    ) {
        unauthorized("Session sender may not add member accounts");
    }
    if (
        removedAccounts.some(
            ([account, removed]) =>
                equalBytes(removed, current.ownerAccount) ||
                (!isAdmin(current, senderAccount) && account !== encodeBase64Url(senderAccount)),
        )
    ) {
        unauthorized("Session sender may not remove member accounts");
    }

    const currentAdmins = accountMap(current.admins);
    const nextAdmins = accountMap(control.roles.admins);
    const granted = [...nextAdmins].filter(([account]) => !currentAdmins.has(account));
    const revoked = [...currentAdmins].filter(([account]) => !nextAdmins.has(account));
    if (
        granted.length > 0 &&
        !equalBytes(senderAccount, current.ownerAccount) &&
        !(isAdmin(current, senderAccount) && current.adminsAssignAdmins)
    ) {
        unauthorized("Session sender may not grant admin");
    }
    if (
        revoked.some(
            ([account]) =>
                !equalBytes(senderAccount, current.ownerAccount) &&
                !(account === encodeBase64Url(senderAccount) && !nextMembers.has(account)),
        )
    ) {
        unauthorized("Session sender may not revoke admin");
    }
    if (
        (current.adminsAssignAdmins !== control.roles.adminsAssignAdmins ||
            current.anyoneCanAddMembers !== control.roles.anyoneCanAddMembers ||
            current.sendPolicy !== control.roles.sendPolicy) &&
        !equalBytes(senderAccount, current.ownerAccount)
    ) {
        unauthorized("Only the session owner may change policies");
    }

    const nextState: RelaySessionState = {
        sessionId,
        epoch: current.epoch + 1n,
        ownerAccount: current.ownerAccount,
        members: control.members,
        rosterRevisions: current.rosterRevisions,
        admins: control.roles.admins,
        adminsAssignAdmins: control.roles.adminsAssignAdmins,
        anyoneCanAddMembers: control.roles.anyoneCanAddMembers,
        sendPolicy: control.roles.sendPolicy,
    };
    return {
        nextState,
        stateChanged: true,
        fanoutAccounts: sortedAccounts([...current.members, ...control.members]),
        coverageAccounts: control.members,
    };
}
