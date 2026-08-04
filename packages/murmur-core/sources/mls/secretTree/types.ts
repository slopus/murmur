/** MLS content ratchet selected for a sender. */
export type MlsRatchetType = "handshake" | "application";

/** One-time key and nonce for a sender generation. */
export interface MlsGenerationKey {
    readonly sender: number;
    readonly generation: number;
    readonly type: MlsRatchetType;
    readonly key: Uint8Array;
    readonly nonce: Uint8Array;
}

/** Durable state for one initialized sender/content ratchet. */
export interface MlsSecretTreeRatchetState {
    readonly sender: number;
    readonly type: MlsRatchetType;
    readonly secret: Uint8Array;
    readonly generation: number;
    readonly skipped: readonly MlsGenerationKey[];
}

/** Sensitive durable snapshot of one mutable epoch Secret Tree. */
export interface MlsSecretTreeState {
    readonly leafCount: number;
    readonly maximumForwardDistance: number;
    readonly maximumSkippedKeys: number;
    readonly nodeSecrets: readonly {
        readonly node: number;
        readonly secret: Uint8Array;
    }[];
    readonly ratchets: readonly MlsSecretTreeRatchetState[];
}
