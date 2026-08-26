/** One signed claim about the roster revision used to expand an account target. */
export interface DeliveryAccountTarget {
    readonly accountKey: Uint8Array;
    readonly rosterRevision: number;
}

/** Relay-visible role state authenticated beside an encrypted MLS delivery. */
export interface DeliverySessionRoles {
    readonly owner: Uint8Array;
    readonly admins: readonly Uint8Array[];
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
    readonly sendPolicy: "everyone" | "admins";
}

/** One MLS leaf change summarized for relay-side role enforcement. */
export interface DeliverySessionMemberChange {
    readonly type: "add" | "remove";
    readonly accountKey: Uint8Array;
    readonly deviceKey: Uint8Array;
}

/** Signed MLS-adjacent metadata used for relay routing and additive checks. */
export type DeliverySessionControl =
    | {
          readonly version: 1;
          readonly type: "create";
          readonly epoch: bigint;
          readonly members: readonly Uint8Array[];
          readonly roles: DeliverySessionRoles;
          readonly coveredDevices: readonly Uint8Array[];
      }
    | {
          readonly version: 1;
          readonly type: "commit";
          readonly epoch: bigint;
          readonly members: readonly Uint8Array[];
          readonly roles: DeliverySessionRoles;
          readonly changes: readonly DeliverySessionMemberChange[];
          readonly coveredDevices: readonly Uint8Array[];
      }
    | {
          readonly version: 1;
          readonly type: "message";
          readonly epoch: bigint;
          readonly content: "application" | "protocol";
          readonly coveredDevices: readonly Uint8Array[];
      };

/** JSON representation of relay-visible session control. */
export type DeliverySessionControlJson =
    | {
          readonly version: 1;
          readonly type: "create";
          readonly epoch: string;
          readonly members: readonly string[];
          readonly roles: DeliverySessionRolesJson;
          readonly coveredDevices: readonly string[];
      }
    | {
          readonly version: 1;
          readonly type: "commit";
          readonly epoch: string;
          readonly members: readonly string[];
          readonly roles: DeliverySessionRolesJson;
          readonly changes: readonly {
              readonly type: "add" | "remove";
              readonly accountKey: string;
              readonly deviceKey: string;
          }[];
          readonly coveredDevices: readonly string[];
      }
    | {
          readonly version: 1;
          readonly type: "message";
          readonly epoch: string;
          readonly content: "application" | "protocol";
          readonly coveredDevices: readonly string[];
      };

/** JSON representation of relay-visible session roles. */
export interface DeliverySessionRolesJson {
    readonly owner: string;
    readonly admins: readonly string[];
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
    readonly sendPolicy: "everyone" | "admins";
}

/** One signed encrypted multicast delivery accepted by the relay. */
export interface SignedDelivery {
    readonly version: 1;
    /** Stable sender-scoped identifier used while the delivery remains pending. */
    readonly id: string;
    /** Public Murmur identity that signed and published this delivery. */
    readonly sender: Uint8Array;
    /** Account that owns this outbound relay state. */
    readonly senderAccount: Uint8Array;
    /** Strictly sorted unique public identities receiving the same ciphertext. */
    readonly recipients: readonly Uint8Array[];
    /** Exact logical account-roster revisions used to select recipient inboxes. */
    readonly targetAccounts: readonly DeliveryAccountTarget[];
    /** Owning account for session-linked cleanup, or null for account traffic. */
    readonly ownerAccount: Uint8Array | null;
    /** Owning MLS session identifier, or null for account traffic. */
    readonly sessionId: Uint8Array | null;
    /** Relay-visible signed control for session-addressed publication, otherwise null. */
    readonly sessionControl: DeliverySessionControl | null;
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
    readonly senderAccount: string;
    readonly recipients: readonly string[];
    readonly targetAccounts: readonly {
        readonly accountKey: string;
        readonly rosterRevision: number;
    }[];
    readonly ownerAccount: string | null;
    readonly sessionId: string | null;
    readonly sessionControl: DeliverySessionControlJson | null;
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

/** One one-use directory KeyPackage and its pre-authorized spent notification. */
export interface DirectoryOneTimePrekey {
    readonly reference: Uint8Array;
    readonly keyPackage: Uint8Array;
    readonly expiresAt: number;
    readonly spentNotification: SignedDelivery;
}

/** One multi-use last-resort directory KeyPackage. */
export interface DirectoryLastResortPrekey {
    readonly reference: Uint8Array;
    readonly keyPackage: Uint8Array;
    readonly expiresAt: number;
}

/** Account-signed directory state carried by an otherwise recipient-less delivery. */
export interface DirectoryPrekeyUpload {
    readonly version: 1;
    readonly type: "directory_prekey_upload";
    readonly mode: "replenish" | "rotate";
    readonly deviceKey: Uint8Array;
    readonly resetGeneration: number;
    readonly oneTimePrekeys: readonly DirectoryOneTimePrekey[];
    readonly lastResort: DirectoryLastResortPrekey;
}

/** One exact device entry returned by a ticket-authorized directory claim. */
export interface DirectoryClaimDevice {
    readonly deviceKey: Uint8Array;
    readonly resetGeneration: number;
    readonly keyPackage: Uint8Array;
    readonly source: "one_time" | "last_resort";
}

/** Exact-account directory result; unknown accounts use revision zero and no devices. */
export interface DirectoryClaim {
    readonly version: 1;
    readonly accountKey: Uint8Array;
    readonly rosterRevision: number;
    readonly devices: readonly DirectoryClaimDevice[];
}
