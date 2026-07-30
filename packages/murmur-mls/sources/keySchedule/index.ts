import {
    MLS_HASH_LENGTH,
    mlsDeriveSecret,
    mlsExpandWithLabel,
    mlsExtract,
} from "../cipherSuite/index.js";
import { zeroBytes } from "@murmur/core";
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
    try {
        return deriveMlsEpochSecretsFromJoiner(joinerSecret, groupContext, pskSecret);
    } finally {
        zeroBytes(joinerSecret);
    }
}

/** Continue the RFC 9420 key schedule from a Welcome GroupSecrets value. */
export function deriveMlsEpochSecretsFromJoiner(
    joinerSecret: Uint8Array,
    groupContext: Uint8Array,
    pskSecret: Uint8Array = new Uint8Array(MLS_HASH_LENGTH),
): MlsEpochSecrets {
    if (joinerSecret.length !== MLS_HASH_LENGTH || pskSecret.length !== MLS_HASH_LENGTH) {
        throw new Error("MLS joiner and PSK secrets must be 32 bytes");
    }

    const completed: Uint8Array[] = [];
    const retain = (secret: Uint8Array): Uint8Array => {
        completed.push(secret);
        return secret;
    };
    try {
        const joinerSecretCopy = retain(joinerSecret.slice());
        const memberSecret = retain(
            mlsExpandWithLabel(joinerSecret, "member", groupContext, MLS_HASH_LENGTH),
        );
        const epochSecret = retain(mlsExtract(memberSecret, pskSecret));

        return {
            joinerSecret: joinerSecretCopy,
            memberSecret,
            epochSecret,
            senderDataSecret: retain(mlsDeriveSecret(epochSecret, "sender data")),
            encryptionSecret: retain(mlsDeriveSecret(epochSecret, "encryption")),
            exporterSecret: retain(mlsDeriveSecret(epochSecret, "exporter")),
            epochAuthenticator: retain(mlsDeriveSecret(epochSecret, "epoch authenticator")),
            externalSecret: retain(mlsDeriveSecret(epochSecret, "external")),
            confirmationKey: retain(mlsDeriveSecret(epochSecret, "confirm")),
            membershipKey: retain(mlsDeriveSecret(epochSecret, "membership")),
            resumptionPsk: retain(mlsDeriveSecret(epochSecret, "resumption")),
            nextInitSecret: retain(mlsDeriveSecret(epochSecret, "init")),
        };
    } catch (error: unknown) {
        for (const secret of completed) {
            zeroBytes(secret);
        }
        throw error;
    }
}

/** Zero every secret retained for one completed MLS epoch. */
export function destroyMlsEpochSecrets(secrets: MlsEpochSecrets): void {
    for (const secret of [
        secrets.joinerSecret,
        secrets.memberSecret,
        secrets.epochSecret,
        secrets.senderDataSecret,
        secrets.encryptionSecret,
        secrets.exporterSecret,
        secrets.epochAuthenticator,
        secrets.externalSecret,
        secrets.confirmationKey,
        secrets.membershipKey,
        secrets.resumptionPsk,
        secrets.nextInitSecret,
    ]) {
        zeroBytes(secret);
    }
}
