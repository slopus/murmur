/** A recursively immutable JSON value accepted in a contact profile. */
export type MurmurContactProfileValue =
    | boolean
    | null
    | number
    | string
    | readonly MurmurContactProfileValue[]
    | { readonly [key: string]: MurmurContactProfileValue };

/** Application-defined public profile exchanged during the contact handshake. */
export type MurmurContactProfile = Readonly<Record<string, MurmurContactProfileValue>>;

/** One confirmed contact and its durable two-person technical session. */
export interface MurmurContact {
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly localProfile: MurmurContactProfile;
    readonly profile: MurmurContactProfile;
    readonly status: "active" | "removing";
}

/** One validated incoming contact hello awaiting an explicit decision. */
export interface MurmurContactRequest {
    /** Stable identifier used to deduplicate callback effects. */
    readonly id: string;
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly profile: MurmurContactProfile;
}

/** One durable outgoing contact handshake awaiting the remote decision. */
export interface MurmurOutgoingContactRequest {
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly createdAt: number;
}

/** Contact-request lifecycle update delivered by the identity-wide sync loop. */
export interface MurmurContactRequested extends MurmurContactRequest {}

/** Contact-confirmation lifecycle update delivered by the identity-wide sync loop. */
export interface MurmurContactAdded {
    /** Stable identifier used to deduplicate callback effects. */
    readonly id: string;
    readonly contact: MurmurContact;
}

/** Contact-removal lifecycle update delivered by the identity-wide sync loop. */
export interface MurmurContactRemoved {
    /** Stable identifier used to deduplicate callback effects. */
    readonly id: string;
    readonly identity: Uint8Array;
    readonly sessionId: Uint8Array;
}

/** Public MLS admission material cached for one confirmed contact relationship. */
export interface MurmurContactAdmission {
    readonly generation: number;
    readonly oneTimeKeyPackages: readonly Uint8Array[];
    readonly lastResortKeyPackage: Uint8Array;
}

/** Versioned packet carried by a technical contact session. */
export type MurmurContactPacket =
    | {
          readonly version: 2;
          readonly type: "hello";
          readonly profile: MurmurContactProfile;
          readonly admission: MurmurContactAdmission;
      }
    | {
          readonly version: 2;
          readonly type: "remove";
      }
    | {
          readonly version: 2;
          readonly type: "admission_request";
          readonly generation: number;
      }
    | {
          readonly version: 2;
          readonly type: "admission_response";
          readonly admission: MurmurContactAdmission;
      };
