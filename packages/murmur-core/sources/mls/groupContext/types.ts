/** RFC 9420 GroupContext without negotiated extensions. */
export interface MlsGroupContext {
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly treeHash: Uint8Array;
    readonly confirmedTranscriptHash: Uint8Array;
}
