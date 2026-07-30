/** RFC 9420 secrets produced for one epoch. */
export interface MlsEpochSecrets {
    readonly joinerSecret: Uint8Array;
    readonly memberSecret: Uint8Array;
    readonly epochSecret: Uint8Array;
    readonly senderDataSecret: Uint8Array;
    readonly encryptionSecret: Uint8Array;
    readonly exporterSecret: Uint8Array;
    readonly epochAuthenticator: Uint8Array;
    readonly externalSecret: Uint8Array;
    readonly confirmationKey: Uint8Array;
    readonly membershipKey: Uint8Array;
    readonly resumptionPsk: Uint8Array;
    readonly nextInitSecret: Uint8Array;
}
