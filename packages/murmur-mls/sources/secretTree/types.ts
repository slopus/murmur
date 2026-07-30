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
