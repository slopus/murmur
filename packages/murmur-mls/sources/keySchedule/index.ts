import {
    MLS_HASH_LENGTH,
    mlsDeriveSecret,
    mlsExpandWithLabel,
    mlsExtract,
} from "../cipherSuite/index.js";
import type { MlsEpochSecrets } from "./types.js";

export type { MlsEpochSecrets } from "./types.js";

/** Derive the RFC 9420 secret tree roots for one epoch. */
export function deriveMlsEpochSecrets(
    initSecret: Uint8Array,
    commitSecret: Uint8Array,
    groupContext: Uint8Array,
    pskSecret: Uint8Array = new Uint8Array(MLS_HASH_LENGTH),
): MlsEpochSecrets {
    if (
        initSecret.length !== MLS_HASH_LENGTH ||
        commitSecret.length !== MLS_HASH_LENGTH ||
        pskSecret.length !== MLS_HASH_LENGTH
    ) {
        throw new Error("MLS key-schedule inputs must be 32 bytes");
    }

    const joinerSecret = mlsExtract(initSecret, commitSecret);
    const memberSecret = mlsExpandWithLabel(joinerSecret, "member", groupContext, MLS_HASH_LENGTH);
    const epochSecret = mlsExtract(memberSecret, pskSecret);

    return {
        joinerSecret,
        memberSecret,
        epochSecret,
        senderDataSecret: mlsDeriveSecret(epochSecret, "sender data"),
        encryptionSecret: mlsDeriveSecret(epochSecret, "encryption"),
        exporterSecret: mlsDeriveSecret(epochSecret, "exporter"),
        epochAuthenticator: mlsDeriveSecret(epochSecret, "epoch authenticator"),
        externalSecret: mlsDeriveSecret(epochSecret, "external"),
        confirmationKey: mlsDeriveSecret(epochSecret, "confirm"),
        membershipKey: mlsDeriveSecret(epochSecret, "membership"),
        resumptionPsk: mlsDeriveSecret(epochSecret, "resumption"),
        nextInitSecret: mlsDeriveSecret(epochSecret, "init"),
    };
}
