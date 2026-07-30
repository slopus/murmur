import type { MlsGroupContext } from "../groupContext/index.js";
import type { MlsEpochSecrets } from "../keySchedule/index.js";

/** Public member data needed to authenticate one MLS epoch. */
export interface MlsEpochMember {
    readonly signatureKey: Uint8Array;
}

/** Inputs for taking ownership of a fully authenticated RFC 9420 epoch. */
export interface CreateMlsEpochOptions {
    readonly context: MlsGroupContext;
    readonly secrets: MlsEpochSecrets;
    readonly members: readonly (MlsEpochMember | undefined)[];
    readonly localLeaf: number;
    readonly localSigningSecretKey: Uint8Array;
}
