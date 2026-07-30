import type {
    Contact,
    IdentityKeyPair,
    IdentityProfile,
    IdentityPublicKeys,
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
}

/** Contact type re-exported for programmatic CLI consumers. */
export type CliContact = Contact;
