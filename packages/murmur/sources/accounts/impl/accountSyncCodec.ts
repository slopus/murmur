import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
} from "../../utils/index.js";

const DESCRIPTOR = canonicalJsonBytes({ protocol: "murmur.account-sync", version: 1 });
const MAXIMUM_PACKET_BYTES = 2 * 1024 * 1024;

/** Built-in account synchronization packet carried inside an MLS session. */
export type AccountSyncPacket =
    | {
          readonly version: 1;
          readonly type: "admission";
          readonly roster: Uint8Array;
          readonly keyPackage: Uint8Array;
      }
    | {
          readonly version: 1;
          readonly type: "roster";
          readonly roster: Uint8Array;
      };

/** Return the private descriptor for one built-in account synchronization session. */
export function accountSyncSessionDescriptor(): Uint8Array {
    return DESCRIPTOR.slice();
}

/** Check the exact built-in account synchronization descriptor. */
export function isAccountSyncSessionDescriptor(value: Uint8Array): boolean {
    return equalBytes(value, DESCRIPTOR);
}

/** Encode one strict account synchronization packet. */
export function encodeAccountSyncPacket(packet: AccountSyncPacket): Uint8Array {
    const bytes = canonicalJsonBytes({
        version: 1,
        type: packet.type,
        roster: encodeBase64Url(packet.roster),
        ...(packet.type === "admission" ? { keyPackage: encodeBase64Url(packet.keyPackage) } : {}),
    });
    if (bytes.length > MAXIMUM_PACKET_BYTES) throw new Error("Account sync packet is too large");
    return bytes;
}

/** Decode one strict account synchronization packet. */
export function decodeAccountSyncPacket(value: Uint8Array): AccountSyncPacket {
    if (value.length < 1 || value.length > MAXIMUM_PACKET_BYTES) {
        throw new Error("Invalid account sync packet");
    }
    const parsed = JSON.parse(utf8Decode(value)) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Invalid account sync packet");
    }
    const input = parsed as Record<string, unknown>;
    const fields =
        input.type === "admission"
            ? ["version", "type", "roster", "keyPackage"]
            : ["version", "type", "roster"];
    if (
        input.version !== 1 ||
        (input.type !== "admission" && input.type !== "roster") ||
        typeof input.roster !== "string" ||
        (input.type === "admission" && typeof input.keyPackage !== "string") ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new Error("Invalid account sync packet");
    }
    const packet: AccountSyncPacket =
        input.type === "admission"
            ? {
                  version: 1,
                  type: "admission",
                  roster: decodeBase64Url(input.roster),
                  keyPackage: decodeBase64Url(input.keyPackage as string),
              }
            : {
                  version: 1,
                  type: "roster",
                  roster: decodeBase64Url(input.roster),
              };
    if (!equalBytes(encodeAccountSyncPacket(packet), value)) {
        throw new Error("Non-canonical account sync packet");
    }
    return packet;
}
