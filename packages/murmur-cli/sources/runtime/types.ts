import type {
    Contact,
    IdentityKeyPair,
    IdentityProfile,
    IdentityPublicKeys,
    DocumentOperation,
    PrivateMessage,
} from "@murmur/core";

/** Durable local account owned by one CLI data directory. */
export interface CliAccount {
    readonly identity: IdentityKeyPair;
    readonly profile: IdentityProfile;
}

/** File bytes supplied to an outgoing private message. */
export interface CliAttachmentInput {
    readonly name: string;
    readonly bytes: Uint8Array;
    readonly mediaType?: string;
}

/** One locally persisted incoming or outgoing private message. */
export interface CliStoredMessage {
    readonly sequence: number;
    readonly direction: "incoming" | "outgoing";
    readonly conversationId: string;
    readonly status: "received" | "pending" | "sent";
    readonly message: PrivateMessage;
}

/** Authenticated application payload carried by one MLS PrivateMessage. */
export interface CliGroupMessage {
    readonly id: string;
    readonly sentAt: number;
    readonly text: string;
}

/** One durable incoming or outgoing MLS group message. */
export interface CliStoredGroupMessage {
    readonly sequence: number;
    readonly groupId: string;
    readonly direction: "incoming" | "outgoing";
    readonly status: "received" | "pending" | "sent";
    readonly sender: number;
    readonly message: CliGroupMessage;
}

/** Public summary of one locally owned MLS group. */
export interface CliGroupSummary {
    readonly id: string;
    readonly name: string;
    readonly epoch: bigint;
    readonly members: readonly (string | undefined)[];
}

/** Rendered local view of one convergent shared text document. */
export interface CliDocumentSummary {
    readonly id: string;
    readonly groupId: string;
    readonly name: string;
    readonly text: string;
    readonly operationCount: number;
    readonly operations: readonly DocumentOperation[];
}

/** Stable public account information safe to print or exchange. */
export interface CliPublicIdentity {
    readonly id: string;
    readonly token: string;
    readonly identity: IdentityPublicKeys;
    readonly profile: IdentityProfile;
}

/** Result of processing one bounded relay synchronization pass. */
export interface CliSyncResult {
    readonly profiles: number;
    readonly messages: number;
    readonly duplicates: number;
    readonly deferred: number;
    readonly retriedOutbound: number;
    readonly retryFailures: number;
    readonly quarantined: number;
    readonly groupMessages: number;
    readonly groupCommits: number;
    readonly invitations: number;
    readonly documentUpdates: number;
}

/** Contact type re-exported for programmatic CLI consumers. */
export type CliContact = Contact;
