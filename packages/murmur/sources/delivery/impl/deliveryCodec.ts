import type { IdentityKeyPair } from "../../crypto/index.js";
import {
    randomBytes,
    signBytes,
    validateIdentityPublicKey,
    verifyBytes,
} from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Encode,
} from "../../utils/index.js";
import type {
    CreateDeliveryOptions,
    CreateInboxReadOptions,
    DeliverySessionControl,
    DeliverySessionRoles,
    InboxDelivery,
    InboxContinuity,
    SignedDelivery,
    SignedInboxAck,
    SignedInboxRead,
} from "../types.js";

const DELIVERY_DOMAIN = "murmur.relay.delivery.v1";
const READ_DOMAIN = "murmur.relay.queue-read.v1";
const ACK_DOMAIN = "murmur.relay.queue-ack.v1";
const MAXIMUM_INBOX_READ_ITEMS = 256;
const MAXIMUM_INBOX_WAIT_MILLISECONDS = 30_000;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAXIMUM_SESSION_IDENTITIES = 1_024;
const MAXIMUM_UINT64 = 0xffff_ffff_ffff_ffffn;

interface DeliverySessionRolesJson {
    readonly owner: string;
    readonly admins: readonly string[];
    readonly adminsAssignAdmins: boolean;
    readonly anyoneCanAddMembers: boolean;
    readonly sendPolicy: "everyone" | "admins";
}

type DeliverySessionControlJson =
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

export interface SignedInboxReadJson {
    readonly version: 1;
    readonly recipient: string;
    readonly after: string | null;
    readonly limit: number;
    readonly waitMilliseconds: number;
    readonly createdAt: number;
    readonly signature: string;
}

export interface SignedInboxAckJson {
    readonly version: 1;
    readonly recipient: string;
    readonly through: string;
    readonly createdAt: number;
    readonly signature: string;
}

function object(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, fields: readonly string[], name: string): void {
    if (
        fields.some((field) => !Object.hasOwn(value, field)) ||
        Object.keys(value).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
}

function safeInteger(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < left.length; index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return 0;
}

function compareChanges(
    left: Extract<DeliverySessionControl, { type: "commit" }>["changes"][number],
    right: Extract<DeliverySessionControl, { type: "commit" }>["changes"][number],
): number {
    const type = left.type.localeCompare(right.type);
    if (type !== 0) return type;
    const account = compareBytes(left.accountKey, right.accountKey);
    return account === 0 ? compareBytes(left.deviceKey, right.deviceKey) : account;
}

function sessionRolesToJson(roles: DeliverySessionRoles): DeliverySessionRolesJson {
    return {
        owner: encodeBase64Url(roles.owner),
        admins: roles.admins.map(encodeBase64Url),
        adminsAssignAdmins: roles.adminsAssignAdmins,
        anyoneCanAddMembers: roles.anyoneCanAddMembers,
        sendPolicy: roles.sendPolicy,
    };
}

function sessionControlToJson(control: DeliverySessionControl): DeliverySessionControlJson {
    const common = {
        version: 1 as const,
        epoch: control.epoch.toString(),
        coveredDevices: control.coveredDevices.map(encodeBase64Url),
    };
    if (control.type === "message") {
        return { ...common, type: "message", content: control.content };
    }
    const state = {
        members: control.members.map(encodeBase64Url),
        roles: sessionRolesToJson(control.roles),
    };
    return control.type === "create"
        ? { ...common, ...state, type: "create" }
        : {
              ...common,
              ...state,
              type: "commit",
              changes: control.changes.map((change) => ({
                  type: change.type,
                  accountKey: encodeBase64Url(change.accountKey),
                  deviceKey: encodeBase64Url(change.deviceKey),
              })),
          };
}

function decimalUint64(value: unknown, name: string): bigint {
    if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = BigInt(value);
    if (decoded > MAXIMUM_UINT64) throw new Error(`Invalid ${name}`);
    return decoded;
}

function sessionRolesFromJson(value: unknown): DeliverySessionRoles {
    const input = object(value, "delivery session roles");
    exact(
        input,
        ["owner", "admins", "adminsAssignAdmins", "anyoneCanAddMembers", "sendPolicy"],
        "delivery session roles",
    );
    if (
        typeof input.owner !== "string" ||
        !Array.isArray(input.admins) ||
        input.admins.some((admin) => typeof admin !== "string") ||
        typeof input.adminsAssignAdmins !== "boolean" ||
        typeof input.anyoneCanAddMembers !== "boolean" ||
        (input.sendPolicy !== "everyone" && input.sendPolicy !== "admins")
    ) {
        throw new Error("Invalid delivery session roles");
    }
    return {
        owner: decodeBase64Url(input.owner),
        admins: input.admins.map((admin) => decodeBase64Url(admin as string)),
        adminsAssignAdmins: input.adminsAssignAdmins,
        anyoneCanAddMembers: input.anyoneCanAddMembers,
        sendPolicy: input.sendPolicy,
    };
}

function sessionControlFromJson(value: unknown): DeliverySessionControl | null {
    if (value === null) return null;
    const input = object(value, "delivery session control");
    if (input.type === "message") {
        exact(
            input,
            ["version", "type", "epoch", "content", "coveredDevices"],
            "delivery session control",
        );
        if (
            input.version !== 1 ||
            (input.content !== "application" && input.content !== "protocol") ||
            !Array.isArray(input.coveredDevices) ||
            input.coveredDevices.some((device) => typeof device !== "string")
        ) {
            throw new Error("Invalid delivery session control");
        }
        return {
            version: 1,
            type: "message",
            epoch: decimalUint64(input.epoch, "delivery session epoch"),
            content: input.content,
            coveredDevices: input.coveredDevices.map((device) => decodeBase64Url(device as string)),
        };
    }
    if (input.type !== "create" && input.type !== "commit") {
        throw new Error("Invalid delivery session control");
    }
    exact(
        input,
        [
            "version",
            "type",
            "epoch",
            "members",
            "roles",
            ...(input.type === "commit" ? ["changes"] : []),
            "coveredDevices",
        ],
        "delivery session control",
    );
    if (
        input.version !== 1 ||
        !Array.isArray(input.members) ||
        input.members.some((member) => typeof member !== "string") ||
        !Array.isArray(input.coveredDevices) ||
        input.coveredDevices.some((device) => typeof device !== "string")
    ) {
        throw new Error("Invalid delivery session control");
    }
    const common = {
        version: 1 as const,
        epoch: decimalUint64(input.epoch, "delivery session epoch"),
        members: input.members.map((member) => decodeBase64Url(member as string)),
        roles: sessionRolesFromJson(input.roles),
        coveredDevices: input.coveredDevices.map((device) => decodeBase64Url(device as string)),
    };
    if (input.type === "create") return { ...common, type: "create" };
    if (!Array.isArray(input.changes)) throw new Error("Invalid delivery session changes");
    return {
        ...common,
        type: "commit",
        changes: input.changes.map((value2) => {
            const change = object(value2, "delivery session change");
            exact(change, ["type", "accountKey", "deviceKey"], "delivery session change");
            if (
                (change.type !== "add" && change.type !== "remove") ||
                typeof change.accountKey !== "string" ||
                typeof change.deviceKey !== "string"
            ) {
                throw new Error("Invalid delivery session change");
            }
            return {
                type: change.type,
                accountKey: decodeBase64Url(change.accountKey),
                deviceKey: decodeBase64Url(change.deviceKey),
            };
        }),
    };
}

function normalizeSessionControl(control: DeliverySessionControl): DeliverySessionControl {
    const common = {
        version: 1 as const,
        epoch: control.epoch,
        coveredDevices: control.coveredDevices.map((device) => device.slice()).sort(compareBytes),
    };
    if (control.type === "message") {
        return { ...common, type: "message", content: control.content };
    }
    const state = {
        members: control.members.map((member) => member.slice()).sort(compareBytes),
        roles: {
            owner: control.roles.owner.slice(),
            admins: control.roles.admins.map((admin) => admin.slice()).sort(compareBytes),
            adminsAssignAdmins: control.roles.adminsAssignAdmins,
            anyoneCanAddMembers: control.roles.anyoneCanAddMembers,
            sendPolicy: control.roles.sendPolicy,
        },
    };
    return control.type === "create"
        ? { ...common, ...state, type: "create" }
        : {
              ...common,
              ...state,
              type: "commit",
              changes: control.changes
                  .map((change) => ({
                      type: change.type,
                      accountKey: change.accountKey.slice(),
                      deviceKey: change.deviceKey.slice(),
                  }))
                  .sort(compareChanges),
          };
}

function validateCanonicalIdentities(values: readonly Uint8Array[], name: string): void {
    if (values.length > MAXIMUM_SESSION_IDENTITIES) throw new Error(`Invalid ${name}`);
    let previous: Uint8Array | undefined;
    for (const value of values) {
        validateIdentityPublicKey({ publicKey: value });
        if (previous !== undefined && compareBytes(previous, value) >= 0) {
            throw new Error(`${name} must be sorted and unique`);
        }
        previous = value;
    }
}

function validateSessionControl(control: DeliverySessionControl): void {
    if (control.version !== 1 || control.epoch < 0n || control.epoch > MAXIMUM_UINT64) {
        throw new Error("Invalid delivery session control");
    }
    validateCanonicalIdentities(control.coveredDevices, "Covered session devices");
    if (control.type === "message") {
        if (control.content !== "application" && control.content !== "protocol") {
            throw new Error("Invalid delivery session message control");
        }
        return;
    }
    validateCanonicalIdentities(control.members, "Delivery session members");
    validateIdentityPublicKey({ publicKey: control.roles.owner });
    validateCanonicalIdentities(control.roles.admins, "Delivery session admins");
    if (
        control.roles.admins.some((admin) => equalBytes(admin, control.roles.owner)) ||
        typeof control.roles.adminsAssignAdmins !== "boolean" ||
        typeof control.roles.anyoneCanAddMembers !== "boolean" ||
        (control.roles.sendPolicy !== "everyone" && control.roles.sendPolicy !== "admins")
    ) {
        throw new Error("Invalid delivery session roles");
    }
    if (control.type === "commit") {
        if (control.changes.length > MAXIMUM_SESSION_IDENTITIES * 2) {
            throw new Error("Invalid delivery session changes");
        }
        let previous: (typeof control.changes)[number] | undefined;
        for (const change of control.changes) {
            validateIdentityPublicKey({ publicKey: change.accountKey });
            validateIdentityPublicKey({ publicKey: change.deviceKey });
            if (
                (change.type !== "add" && change.type !== "remove") ||
                (previous !== undefined && compareChanges(previous, change) >= 0)
            ) {
                throw new Error("Delivery session changes must be sorted and unique");
            }
            previous = change;
        }
    }
}

function validateUuid(value: unknown, name: string): string {
    if (typeof value !== "string" || !UUID_V7.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    return value;
}

function validateDeliveryId(value: string): void {
    const bytes = decodeBase64Url(value);
    if (bytes.length !== 24 || encodeBase64Url(bytes) !== value) {
        throw new Error("Invalid delivery ID");
    }
}

function separated(domain: string, value: Parameters<typeof canonicalJsonBytes>[0]): Uint8Array {
    const prefix = utf8Encode(`${domain}\0`);
    const body = canonicalJsonBytes(value);
    const bytes = new Uint8Array(prefix.length + body.length);
    bytes.set(prefix);
    bytes.set(body, prefix.length);
    return bytes;
}

/** Encode one account-signed session-deletion request body. */
export function encodeSessionDeletionRequest(sessionId: Uint8Array): Uint8Array {
    if (sessionId.length !== 32) throw new Error("Invalid session deletion request");
    return canonicalJsonBytes({
        version: 1,
        type: "delete_session",
        sessionId: encodeBase64Url(sessionId),
    });
}

/** Encode one account-signed terminal account-deletion request body. */
export function encodeAccountDeletionRequest(): Uint8Array {
    return canonicalJsonBytes({ version: 1, type: "delete_account" });
}

/**
 * Encode one delivery for relay JSON from a custom transport implementation.
 */
export function signedDeliveryToJson(delivery: SignedDelivery): SignedDeliveryJson {
    return {
        version: 1,
        id: delivery.id,
        sender: encodeBase64Url(delivery.sender),
        senderAccount: encodeBase64Url(delivery.senderAccount),
        recipients: delivery.recipients.map(encodeBase64Url),
        targetAccounts: delivery.targetAccounts.map((target) => ({
            accountKey: encodeBase64Url(target.accountKey),
            rosterRevision: target.rosterRevision,
        })),
        ownerAccount:
            delivery.ownerAccount === null ? null : encodeBase64Url(delivery.ownerAccount),
        sessionId: delivery.sessionId === null ? null : encodeBase64Url(delivery.sessionId),
        sessionControl:
            delivery.sessionControl === null ? null : sessionControlToJson(delivery.sessionControl),
        createdAt: delivery.createdAt,
        expiresAt: delivery.expiresAt,
        ciphertext: encodeBase64Url(delivery.ciphertext),
        signature: encodeBase64Url(delivery.signature),
    };
}

function deliverySigningBytes(delivery: SignedDelivery): Uint8Array {
    const { signature: _signature, ...unsigned } = signedDeliveryToJson(delivery);
    return separated(
        DELIVERY_DOMAIN,
        unsigned as unknown as Parameters<typeof canonicalJsonBytes>[0],
    );
}

/**
 * Validate the canonical shape of a delivery at a custom transport boundary.
 * This does not verify its sender signature.
 */
export function validateSignedDelivery(delivery: SignedDelivery): void {
    validateDeliveryId(delivery.id);
    validateIdentityPublicKey({ publicKey: delivery.sender });
    validateIdentityPublicKey({ publicKey: delivery.senderAccount });
    if (
        delivery.version !== 1 ||
        !Number.isSafeInteger(delivery.createdAt) ||
        delivery.createdAt < 0 ||
        !Number.isSafeInteger(delivery.expiresAt) ||
        delivery.expiresAt <= delivery.createdAt ||
        delivery.signature.length !== 64
    ) {
        throw new Error("Invalid signed delivery");
    }
    if ((delivery.ownerAccount === null) !== (delivery.sessionId === null)) {
        throw new Error("Invalid signed delivery session ownership");
    }
    if (delivery.ownerAccount !== null)
        validateIdentityPublicKey({ publicKey: delivery.ownerAccount });
    if (delivery.sessionId !== null && delivery.sessionId.length !== 32) {
        throw new Error("Invalid signed delivery session ID");
    }
    if (delivery.sessionControl !== null) {
        if (
            delivery.ownerAccount === null ||
            delivery.sessionId === null ||
            delivery.recipients.length !== 0 ||
            delivery.targetAccounts.length !== 0
        ) {
            throw new Error("Session-addressed delivery must not name recipients");
        }
        validateSessionControl(delivery.sessionControl);
    }
    let previous: Uint8Array | undefined;
    for (const recipient of delivery.recipients) {
        validateIdentityPublicKey({ publicKey: recipient });
        if (previous !== undefined && compareBytes(previous, recipient) >= 0) {
            throw new Error("Delivery recipients must be sorted and unique");
        }
        previous = recipient;
    }
    previous = undefined;
    for (const target of delivery.targetAccounts) {
        validateIdentityPublicKey({ publicKey: target.accountKey });
        if (!Number.isSafeInteger(target.rosterRevision) || target.rosterRevision < 0) {
            throw new Error("Invalid delivery target roster revision");
        }
        if (previous !== undefined && compareBytes(previous, target.accountKey) >= 0) {
            throw new Error("Delivery target accounts must be sorted and unique");
        }
        previous = target.accountKey;
    }
}

/** Verify a delivery received by a custom transport implementation. */
export function verifySignedDelivery(delivery: SignedDelivery): boolean {
    try {
        validateSignedDelivery(delivery);
        return verifyBytes(
            { publicKey: delivery.sender },
            deliverySigningBytes(delivery),
            delivery.signature,
        );
    } catch {
        return false;
    }
}

/** Create an exact sender-signed delivery for a low-level relay integration. */
export function createSignedDelivery(
    identity: IdentityKeyPair,
    recipients: readonly Uint8Array[],
    ciphertext: Uint8Array,
    options: CreateDeliveryOptions,
): SignedDelivery {
    const createdAt = options.createdAt ?? Date.now();
    const unsigned: SignedDelivery = {
        version: 1,
        id: options.id ?? encodeBase64Url(randomBytes(24)),
        sender: identity.publicKey.slice(),
        senderAccount: options.senderAccount?.slice() ?? identity.publicKey.slice(),
        recipients: recipients.map((value) => value.slice()).sort(compareBytes),
        targetAccounts: (options.targetAccounts ?? [])
            .map((target) => ({
                accountKey: target.accountKey.slice(),
                rosterRevision: target.rosterRevision,
            }))
            .sort((left, right) => compareBytes(left.accountKey, right.accountKey)),
        ownerAccount: options.ownerAccount?.slice() ?? null,
        sessionId: options.sessionId?.slice() ?? null,
        sessionControl:
            options.sessionControl === undefined
                ? null
                : normalizeSessionControl(options.sessionControl),
        createdAt,
        expiresAt: options.expiresAt,
        ciphertext: ciphertext.slice(),
        signature: new Uint8Array(64),
    };
    validateSignedDelivery(unsigned);
    return { ...unsigned, signature: signBytes(identity, deliverySigningBytes(unsigned)) };
}

function parseSignedDeliveryValue(value: unknown, validateIdentity: boolean): SignedDelivery {
    const input = object(value, "signed delivery");
    exact(
        input,
        [
            "version",
            "id",
            "sender",
            "senderAccount",
            "recipients",
            "targetAccounts",
            "ownerAccount",
            "sessionId",
            "sessionControl",
            "createdAt",
            "expiresAt",
            "ciphertext",
            "signature",
        ],
        "signed delivery",
    );
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        typeof input.sender !== "string" ||
        typeof input.senderAccount !== "string" ||
        !Array.isArray(input.recipients) ||
        input.recipients.some((entry) => typeof entry !== "string") ||
        !Array.isArray(input.targetAccounts) ||
        (input.ownerAccount !== null && typeof input.ownerAccount !== "string") ||
        (input.sessionId !== null && typeof input.sessionId !== "string") ||
        typeof input.ciphertext !== "string" ||
        typeof input.signature !== "string"
    ) {
        throw new Error("Invalid signed delivery");
    }
    const delivery: SignedDelivery = {
        version: 1,
        id: input.id,
        sender: decodeBase64Url(input.sender),
        senderAccount: decodeBase64Url(input.senderAccount),
        recipients: input.recipients.map((entry) => decodeBase64Url(entry as string)),
        targetAccounts: input.targetAccounts.map((entry) => {
            const target = object(entry, "delivery target account");
            exact(target, ["accountKey", "rosterRevision"], "delivery target account");
            if (typeof target.accountKey !== "string") {
                throw new Error("Invalid delivery target account");
            }
            return {
                accountKey: decodeBase64Url(target.accountKey),
                rosterRevision: safeInteger(
                    target.rosterRevision,
                    "delivery target roster revision",
                ),
            };
        }),
        ownerAccount:
            input.ownerAccount === null ? null : decodeBase64Url(input.ownerAccount as string),
        sessionId: input.sessionId === null ? null : decodeBase64Url(input.sessionId as string),
        sessionControl: sessionControlFromJson(input.sessionControl),
        createdAt: safeInteger(input.createdAt, "delivery timestamp"),
        expiresAt: safeInteger(input.expiresAt, "delivery expiration"),
        ciphertext: decodeBase64Url(input.ciphertext),
        signature: decodeBase64Url(input.signature),
    };
    if (validateIdentity) {
        validateSignedDelivery(delivery);
    } else {
        validateDeliveryId(delivery.id);
        if (
            delivery.sender.length !== 32 ||
            delivery.senderAccount.length !== 32 ||
            delivery.version !== 1 ||
            !Number.isSafeInteger(delivery.createdAt) ||
            delivery.createdAt < 0 ||
            !Number.isSafeInteger(delivery.expiresAt) ||
            delivery.expiresAt <= delivery.createdAt ||
            delivery.signature.length !== 64
        ) {
            throw new Error("Invalid signed delivery");
        }
        if (
            (delivery.ownerAccount === null) !== (delivery.sessionId === null) ||
            (delivery.ownerAccount !== null && delivery.ownerAccount.length !== 32) ||
            (delivery.sessionId !== null && delivery.sessionId.length !== 32)
        ) {
            throw new Error("Invalid signed delivery session ownership");
        }
        let previous: Uint8Array | undefined;
        for (const recipient of delivery.recipients) {
            if (recipient.length !== 32) throw new Error("Invalid delivery recipient");
            if (previous !== undefined && compareBytes(previous, recipient) >= 0) {
                throw new Error("Delivery recipients must be sorted and unique");
            }
            previous = recipient;
        }
        previous = undefined;
        for (const target of delivery.targetAccounts) {
            if (
                target.accountKey.length !== 32 ||
                !Number.isSafeInteger(target.rosterRevision) ||
                target.rosterRevision < 0
            ) {
                throw new Error("Invalid delivery target account");
            }
            if (previous !== undefined && compareBytes(previous, target.accountKey) >= 0) {
                throw new Error("Delivery target accounts must be sorted and unique");
            }
            previous = target.accountKey;
        }
    }
    return delivery;
}

/**
 * Parse one strict signed-delivery value for a custom transport implementation.
 */
export function parseSignedDelivery(value: unknown): SignedDelivery {
    return parseSignedDeliveryValue(value, true);
}

/** Encode one signed inbox read for a custom transport's relay request. */
export function signedInboxReadToJson(read: SignedInboxRead): SignedInboxReadJson {
    return {
        version: 1,
        recipient: encodeBase64Url(read.recipient),
        after: read.after,
        limit: read.limit,
        waitMilliseconds: read.waitMilliseconds,
        createdAt: read.createdAt,
        signature: encodeBase64Url(read.signature),
    };
}

function readSigningBytes(read: SignedInboxRead): Uint8Array {
    const { signature: _signature, ...unsigned } = signedInboxReadToJson(read);
    return separated(READ_DOMAIN, unsigned);
}

/** Create a recipient-signed page or stream read for a custom transport. */
export function createSignedInboxRead(
    identity: IdentityKeyPair,
    options: CreateInboxReadOptions = {},
): SignedInboxRead {
    const read: SignedInboxRead = {
        version: 1,
        recipient: identity.publicKey.slice(),
        after: options.after ?? null,
        limit: options.limit ?? 256,
        waitMilliseconds: options.waitMilliseconds ?? 0,
        createdAt: options.createdAt ?? Date.now(),
        signature: new Uint8Array(64),
    };
    if (
        (read.after !== null && !UUID_V7.test(read.after)) ||
        !Number.isSafeInteger(read.limit) ||
        read.limit < 1 ||
        read.limit > MAXIMUM_INBOX_READ_ITEMS ||
        !Number.isSafeInteger(read.waitMilliseconds) ||
        read.waitMilliseconds < 0 ||
        read.waitMilliseconds > MAXIMUM_INBOX_WAIT_MILLISECONDS ||
        !Number.isSafeInteger(read.createdAt) ||
        read.createdAt < 0
    ) {
        throw new Error("Invalid inbox read");
    }
    return { ...read, signature: signBytes(identity, readSigningBytes(read)) };
}

/** Encode one signed inbox acknowledgement for a custom transport's relay request. */
export function signedInboxAckToJson(ack: SignedInboxAck): SignedInboxAckJson {
    return {
        version: 1,
        recipient: encodeBase64Url(ack.recipient),
        through: ack.through,
        createdAt: ack.createdAt,
        signature: encodeBase64Url(ack.signature),
    };
}

function ackSigningBytes(ack: SignedInboxAck): Uint8Array {
    const { signature: _signature, ...unsigned } = signedInboxAckToJson(ack);
    return separated(ACK_DOMAIN, unsigned);
}

/** Create a recipient-signed acknowledgement for a custom transport. */
export function createSignedInboxAck(
    identity: IdentityKeyPair,
    through: string,
    createdAt: number = Date.now(),
): SignedInboxAck {
    validateUuid(through, "inbox acknowledgement");
    safeInteger(createdAt, "acknowledgement timestamp");
    const ack: SignedInboxAck = {
        version: 1,
        recipient: identity.publicKey.slice(),
        through,
        createdAt,
        signature: new Uint8Array(64),
    };
    return { ...ack, signature: signBytes(identity, ackSigningBytes(ack)) };
}

/** Parse one bounded relay page returned by a custom transport implementation. */
export function parseInboxPage(
    value: unknown,
    maximumDeliveries: number = MAXIMUM_INBOX_READ_ITEMS,
): {
    readonly deliveries: readonly InboxDelivery[];
    readonly head: string | null;
    readonly headSequence: number;
    readonly acknowledgedThrough: string | null;
    readonly acknowledgedSequence: number;
    readonly generation: Uint8Array;
    readonly exhausted: boolean;
} {
    const input = object(value, "inbox page");
    exact(
        input,
        [
            "deliveries",
            "head",
            "headSequence",
            "acknowledgedThrough",
            "acknowledgedSequence",
            "generation",
            "exhausted",
        ],
        "inbox page",
    );
    if (
        !Number.isSafeInteger(maximumDeliveries) ||
        maximumDeliveries < 1 ||
        maximumDeliveries > MAXIMUM_INBOX_READ_ITEMS ||
        !Array.isArray(input.deliveries) ||
        input.deliveries.length > maximumDeliveries ||
        (input.head !== null && typeof input.head !== "string") ||
        (input.acknowledgedThrough !== null && typeof input.acknowledgedThrough !== "string") ||
        typeof input.generation !== "string" ||
        typeof input.exhausted !== "boolean"
    ) {
        throw new Error("Invalid inbox page");
    }
    return {
        deliveries: input.deliveries.map(parseInboxDelivery),
        head: input.head === null ? null : validateUuid(input.head, "inbox head"),
        headSequence: safeInteger(input.headSequence, "inbox head sequence"),
        acknowledgedThrough:
            input.acknowledgedThrough === null
                ? null
                : validateUuid(input.acknowledgedThrough, "acknowledged event ID"),
        acknowledgedSequence: safeInteger(
            input.acknowledgedSequence,
            "acknowledged inbox sequence",
        ),
        generation: (() => {
            const generation = decodeBase64Url(input.generation);
            if (generation.length !== 32) throw new Error("Invalid inbox generation");
            return generation;
        })(),
        exhausted: input.exhausted,
    };
}

/** Strictly decode one queued delivery from a relay page or SSE event. */
export function parseInboxDelivery(value: unknown): InboxDelivery {
    const queued = object(value, "queued delivery");
    exact(queued, ["eventId", "sequence", "delivery"], "queued delivery");
    return {
        eventId: validateUuid(queued.eventId, "relay event ID"),
        sequence: safeInteger(queued.sequence, "inbox sequence"),
        delivery: parseSignedDeliveryValue(queued.delivery, false),
    };
}

/** Strictly decode one relay stream continuity frame in a custom transport. */
export function parseInboxContinuity(value: unknown): InboxContinuity {
    const input = object(value, "inbox continuity");
    exact(
        input,
        ["generation", "head", "headSequence", "acknowledgedThrough", "acknowledgedSequence"],
        "inbox continuity",
    );
    if (
        typeof input.generation !== "string" ||
        (input.head !== null && typeof input.head !== "string") ||
        (input.acknowledgedThrough !== null && typeof input.acknowledgedThrough !== "string")
    ) {
        throw new Error("Invalid inbox continuity");
    }
    const generation = decodeBase64Url(input.generation);
    if (generation.length !== 32) throw new Error("Invalid inbox continuity");
    return {
        type: "continuity",
        generation,
        head: input.head === null ? null : validateUuid(input.head, "inbox head"),
        headSequence: safeInteger(input.headSequence, "inbox head sequence"),
        acknowledgedThrough:
            input.acknowledgedThrough === null
                ? null
                : validateUuid(input.acknowledgedThrough, "acknowledged event ID"),
        acknowledgedSequence: safeInteger(input.acknowledgedSequence, "acknowledged sequence"),
    };
}

/** Test explicit recipient membership for a direct, non-session delivery. */
export function containsRecipient(delivery: SignedDelivery, recipient: Uint8Array): boolean {
    return delivery.recipients.some((value) => equalBytes(value, recipient));
}
