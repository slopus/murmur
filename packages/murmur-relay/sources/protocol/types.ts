/** One signed encrypted multicast delivery accepted by the relay. */
export interface SignedDelivery {
    readonly version: 1;
    /** Stable sender-scoped identifier used while the delivery remains pending. */
    readonly id: string;
    /** Public Murmur identity that signed and published this delivery. */
    readonly sender: Uint8Array;
    /** Strictly sorted unique public identities receiving the same ciphertext. */
    readonly recipients: readonly Uint8Array[];
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly ciphertext: Uint8Array;
    readonly signature: Uint8Array;
}

/** JSON representation of one signed encrypted multicast delivery. */
export interface SignedDeliveryJson {
    readonly version: 1;
    readonly id: string;
    readonly sender: string;
    readonly recipients: readonly string[];
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly ciphertext: string;
    readonly signature: string;
}

/** Signed request to read one identity's queue. */
export interface SignedQueueRead {
    readonly version: 1;
    readonly recipient: Uint8Array;
    readonly after: string | null;
    readonly limit: number;
    readonly waitMilliseconds: number;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** JSON representation of one signed queue read. */
export interface SignedQueueReadJson {
    readonly version: 1;
    readonly recipient: string;
    readonly after: string | null;
    readonly limit: number;
    readonly waitMilliseconds: number;
    readonly createdAt: number;
    readonly signature: string;
}

/** Signed monotonic request to trim one identity's processed queue prefix. */
export interface SignedQueueAck {
    readonly version: 1;
    readonly recipient: Uint8Array;
    readonly through: string;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** JSON representation of one signed queue acknowledgement. */
export interface SignedQueueAckJson {
    readonly version: 1;
    readonly recipient: string;
    readonly through: string;
    readonly createdAt: number;
    readonly signature: string;
}

/** Owner signature binding exact invitation bytes to a separate revocation key. */
export interface InvitationUploadAuthorization {
    readonly version: 1;
    readonly owner: Uint8Array;
    readonly revocationKey: Uint8Array;
    readonly digest: Uint8Array;
    readonly expiresAt: number;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}

/** Parsed owner-authorized invitation upload wrapper. */
export interface OwnedInvitationUpload {
    readonly version: 1;
    readonly bundle: Uint8Array;
    readonly authorization: InvitationUploadAuthorization;
}

/** Single- or authority-wide invitation revocation request. */
export interface SignedInvitationRevocation {
    readonly version: 1;
    readonly revocationKey: Uint8Array;
    readonly digest: Uint8Array | null;
    readonly createdAt: number;
    readonly signature: Uint8Array;
}
