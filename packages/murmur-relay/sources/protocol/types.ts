/** One signed claim about the roster revision used to expand an account target. */
export interface DeliveryAccountTarget {
    readonly accountKey: Uint8Array;
    readonly rosterRevision: number;
}

/** One signed encrypted multicast delivery accepted by the relay. */
export interface SignedDelivery {
    readonly version: 1;
    /** Stable sender-scoped identifier used while the delivery remains pending. */
    readonly id: string;
    /** Public Murmur identity that signed and published this delivery. */
    readonly sender: Uint8Array;
    /** Strictly sorted unique public identities receiving the same ciphertext. */
    readonly recipients: readonly Uint8Array[];
    /** Exact logical account-roster revisions used to select recipient inboxes. */
    readonly targetAccounts: readonly DeliveryAccountTarget[];
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
    readonly targetAccounts: readonly {
        readonly accountKey: string;
        readonly rosterRevision: number;
    }[];
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

/** One active device in the relay-owned current account roster. */
export interface DeviceRosterEntry {
    readonly deviceKey: Uint8Array;
    readonly resetGeneration: number;
}

/** Current admission material associated with an active roster device. */
export interface DeviceAdmission {
    readonly deviceKey: Uint8Array;
    readonly keyPackage: Uint8Array;
}

/** One current relay-owned account roster. */
export interface DeviceRoster {
    readonly version: 1;
    readonly accountKey: Uint8Array;
    readonly revision: number;
    readonly devices: readonly DeviceRosterEntry[];
    readonly admissions: readonly DeviceAdmission[];
}

/** JSON representation of one current account roster. */
export interface DeviceRosterJson {
    readonly version: 1;
    readonly accountKey: string;
    readonly revision: number;
    readonly devices: readonly { readonly deviceKey: string; readonly resetGeneration: number }[];
    readonly admissions: readonly { readonly deviceKey: string; readonly keyPackage: string }[];
}

/** Plaintext action carried by an account-signed roster-mutation delivery. */
export type DeviceRosterMutation =
    | {
          readonly version: 1;
          readonly type: "register";
          readonly deviceKey: Uint8Array;
          readonly resetGeneration: number;
          readonly keyPackage: Uint8Array;
      }
    | {
          readonly version: 1;
          readonly type: "remove";
          readonly deviceKey: Uint8Array;
          readonly resetGeneration: number;
      };
