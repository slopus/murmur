/** One active device in the relay-owned current account roster. */
export interface MurmurDeviceRosterEntry {
    readonly deviceKey: Uint8Array;
    /** Monotonic continuity-reset generation for this physical device key. */
    readonly resetGeneration: number;
}

/** Current admission material associated with an active roster device. */
export interface MurmurDeviceAdmission {
    readonly deviceKey: Uint8Array;
    readonly keyPackage: Uint8Array;
}

/** One complete current account roster returned by the relay. */
export interface MurmurDeviceRoster {
    readonly version: 1;
    readonly accountKey: Uint8Array;
    readonly revision: number;
    readonly devices: readonly MurmurDeviceRosterEntry[];
    readonly admissions: readonly MurmurDeviceAdmission[];
}

/** Plaintext carried by an identity-signed roster-mutation delivery. */
export type MurmurDeviceRosterMutation =
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

/** Durable local lifecycle notification for one newly registered account device. */
export interface MurmurDeviceAdded {
    readonly id: string;
    readonly account: Uint8Array;
    readonly device: Uint8Array;
    readonly rosterRevision: number;
}

/** Durable local lifecycle notification for one removed account device. */
export interface MurmurDeviceRevoked extends MurmurDeviceAdded {}

/** One active sibling device whose last authenticated activity crossed six months. */
export interface MurmurDormantDevice {
    readonly device: Uint8Array;
    readonly lastActivityAt: number;
    readonly dormantSince: number;
}
