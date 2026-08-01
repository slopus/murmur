/** Public signing identity attached to every relay write. */
export interface RelayAuthor {
    readonly signingKey: Uint8Array;
}

/** Optimistic replacement or deletion of the topic snapshot. */
export interface SnapshotMutation {
    readonly expectedVersion: number;
    readonly bytes?: Uint8Array;
}

/** Append one new opaque list element at the end of the topic order. */
export interface AppendListOperation {
    readonly op: "append";
    readonly id: string;
    readonly bytes: Uint8Array;
}

/** Replace one existing opaque list element without changing its position. */
export interface ReplaceListOperation {
    readonly op: "replace";
    readonly id: string;
    readonly expectedVersion?: number;
    readonly bytes: Uint8Array;
}

/** Delete one existing opaque list element. */
export interface DeleteListOperation {
    readonly op: "delete";
    readonly id: string;
    readonly expectedVersion?: number;
}

/** One ordered list mutation carried by a signed event. */
export type ListOperation = AppendListOperation | ReplaceListOperation | DeleteListOperation;

/** Complete authenticated event accepted by the relay store. */
export interface SignedRelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly author: RelayAuthor;
    readonly createdAt: number;
    readonly payload: Uint8Array;
    readonly snapshot?: SnapshotMutation;
    readonly list?: readonly ListOperation[];
    readonly signature: Uint8Array;
}

/** JSON-compatible representation of a signed event at the HTTP and SQL boundary. */
export interface SignedRelayEventJson {
    readonly version: 1;
    readonly id: string;
    readonly topic: string;
    readonly author: {
        readonly signingKey: string;
    };
    readonly createdAt: number;
    readonly payload: string;
    readonly snapshot?: {
        readonly expectedVersion: number;
        readonly bytes?: string;
    };
    readonly list?: readonly (
        | {
              readonly op: "append";
              readonly id: string;
              readonly bytes: string;
          }
        | {
              readonly op: "replace";
              readonly id: string;
              readonly expectedVersion?: number;
              readonly bytes: string;
          }
        | {
              readonly op: "delete";
              readonly id: string;
              readonly expectedVersion?: number;
          }
    )[];
    readonly signature: string;
}
