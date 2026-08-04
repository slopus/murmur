/** A publicly readable topic whose durable writes require this key. */
export interface WriteTopic {
    readonly type: "write";
    readonly name: string;
    readonly writeKey: Uint8Array;
}

/** A publicly writable topic whose reads require this key. */
export interface ReadTopic {
    readonly type: "read";
    readonly name: string;
    readonly readKey: Uint8Array;
}

/** A topic whose reads and writes require their designated keys. */
export interface ReadWriteTopic {
    readonly type: "read-write";
    readonly name: string;
    readonly readKey: Uint8Array;
    readonly writeKey: Uint8Array;
}

/** Typed, named, key-scoped relay topic descriptor. */
export type RelayTopic = WriteTopic | ReadTopic | ReadWriteTopic;

/** Public signing identity attached to every durable relay write. */
export interface RelayAuthor {
    readonly signingKey: Uint8Array;
}

/** Complete authenticated event accepted by the relay store. */
export interface SignedRelayEvent {
    readonly version: 1;
    readonly id: string;
    readonly topic: RelayTopic;
    readonly author: RelayAuthor;
    readonly createdAt: number;
    readonly expiresAt?: number;
    readonly collapseKey?: Uint8Array;
    readonly payload: Uint8Array;
    readonly signature: Uint8Array;
}

/** JSON-compatible topic descriptor. */
export type RelayTopicJson =
    | { readonly type: "write"; readonly name: string; readonly writeKey: string }
    | { readonly type: "read"; readonly name: string; readonly readKey: string }
    | {
          readonly type: "read-write";
          readonly name: string;
          readonly readKey: string;
          readonly writeKey: string;
      };

/** JSON-compatible signed event representation. */
export interface SignedRelayEventJson {
    readonly version: 1;
    readonly id: string;
    readonly topic: RelayTopicJson;
    readonly author: { readonly signingKey: string };
    readonly createdAt: number;
    readonly expiresAt?: number;
    readonly collapseKey?: string;
    readonly payload: string;
    readonly signature: string;
}

/** One-use relay challenge for a protected read. */
export interface ReadChallenge {
    readonly id: string;
    readonly nonce: Uint8Array;
    readonly expiresAt: number;
}

/** Signature consuming one challenge for exact read parameters. */
export interface ReadProof {
    readonly challengeId: string;
    readonly signature: Uint8Array;
}
