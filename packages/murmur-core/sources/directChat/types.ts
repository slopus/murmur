import type { ReceivedEvent, TopicResetRequired } from "../client/index.js";
import type { IdentityPublicKeys } from "../crypto/index.js";
import type { PrivateMessage } from "../messaging/index.js";
import type { StoreTransaction } from "../storage/index.js";

/**
 * Stable metadata applications can use to order surfaced logical messages.
 *
 * `sentAt` is authenticated as the sender's claim, not trusted relay time.
 */
export interface DirectChatOrdering {
    readonly sentAt: number;
    readonly senderId: string;
    readonly messageId: string;
}

/** One authenticated logical direct message, independent of relay copies. */
export interface DirectChatMessage {
    readonly direction: "incoming" | "outgoing";
    readonly source: "local-send" | "relay";
    readonly topic: string;
    readonly friend: IdentityPublicKeys;
    readonly sender: IdentityPublicKeys;
    readonly message: PrivateMessage;
    readonly ordering: DirectChatOrdering;
}

/** Application persistence hooks invoked only inside MurmurStore transactions. */
export interface DirectChatCallbacks {
    persistMessage(transaction: StoreTransaction, message: DirectChatMessage): Promise<void>;
    messagePublished?(transaction: StoreTransaction, message: DirectChatMessage): Promise<void>;
}

/** Caller-controlled logical send identity and deterministic timestamp. */
export interface DirectChatSendOptions {
    readonly id?: string;
    readonly sentAt?: number;
}

/** Result of handling one event already read by an existing MurmurClient. */
export type DirectChatEventResult =
    | {
          readonly status: "unhandled";
          readonly event: ReceivedEvent;
      }
    | {
          readonly status: "opened" | "duplicate" | "quarantined";
          readonly message?: DirectChatMessage;
      };

/** One bounded direct-chat synchronization pass. */
export type DirectChatSyncResult =
    | {
          readonly status: "events";
          readonly opened: readonly DirectChatMessage[];
          readonly duplicates: number;
          readonly quarantined: number;
          readonly unhandled: readonly ReceivedEvent[];
      }
    | {
          readonly status: "reset";
          readonly resets: readonly TopicResetRequired[];
      };

/** Permanent-list backfill result for one friend and relay. */
export interface DirectChatHistoryResult {
    readonly opened: readonly DirectChatMessage[];
    readonly duplicates: number;
    readonly quarantined: number;
}
