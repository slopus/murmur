import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { RelayError } from "../errors.js";
import type {
    DeliverySessionControl,
    DeliverySessionControlJson,
    DeliverySessionRoles,
    DeliverySessionRolesJson,
    SignedDelivery,
    SignedDeliveryJson,
    SignedQueueAck,
    SignedQueueAckJson,
    SignedQueueRead,
    SignedQueueReadJson,
} from "../types.js";
import { decodeBase64Url, encodeBase64Url, isBase64Url } from "../../utils/base64Url.js";
import { equalBytes } from "../../utils/bytes.js";
import { canonicalJson } from "../../utils/canonicalJson.js";
import { isUuidV7 } from "../../utils/uuidV7.js";

const DELIVERY_ID_BYTES = 24;
const IDENTITY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const MAXIMUM_SESSION_IDENTITIES = 1_024;
const MAXIMUM_UINT64 = 0xffff_ffff_ffff_ffffn;

function objectValue(value: unknown, name: string): Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value as Record<string, unknown>;
}

function exactKeys(
    value: Record<string, unknown>,
    required: readonly string[],
    name: string,
): void {
    const allowed = new Set(required);
    if (
        required.some((key) => !Object.hasOwn(value, key)) ||
        Object.keys(value).some((key) => !allowed.has(key))
    ) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function safeInteger(value: unknown, name: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function eventCursor(value: unknown, name: string): string {
    if (typeof value !== "string" || !isUuidV7(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return value;
}

function bytesValue(value: unknown, name: string, expectedBytes?: number): Uint8Array {
    if (typeof value !== "string") {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    try {
        return decodeBase64Url(value, expectedBytes);
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
    for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
        const difference = (left[index] ?? 0) - (right[index] ?? 0);
        if (difference !== 0) return difference;
    }
    return left.length - right.length;
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

function decimalUint64(value: unknown, name: string): bigint {
    if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    const decoded = BigInt(value);
    if (decoded > MAXIMUM_UINT64) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    return decoded;
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

function parseSessionRoles(value: unknown): DeliverySessionRoles {
    const input = objectValue(value, "delivery session roles");
    exactKeys(
        input,
        ["owner", "admins", "adminsAssignAdmins", "anyoneCanAddMembers", "sendPolicy"],
        "delivery session roles",
    );
    if (
        !Array.isArray(input.admins) ||
        typeof input.adminsAssignAdmins !== "boolean" ||
        typeof input.anyoneCanAddMembers !== "boolean" ||
        (input.sendPolicy !== "everyone" && input.sendPolicy !== "admins")
    ) {
        throw new RelayError(400, "Invalid delivery session roles", { error: "malformed" });
    }
    return {
        owner: bytesValue(input.owner, "delivery session owner", IDENTITY_BYTES),
        admins: input.admins.map((admin) =>
            bytesValue(admin, "delivery session admin", IDENTITY_BYTES),
        ),
        adminsAssignAdmins: input.adminsAssignAdmins,
        anyoneCanAddMembers: input.anyoneCanAddMembers,
        sendPolicy: input.sendPolicy,
    };
}

function parseSessionControl(value: unknown): DeliverySessionControl | null {
    if (value === null) return null;
    const input = objectValue(value, "delivery session control");
    if (input.type === "message") {
        exactKeys(
            input,
            ["version", "type", "epoch", "content", "coveredDevices"],
            "delivery session control",
        );
        if (
            input.version !== 1 ||
            (input.content !== "application" && input.content !== "protocol") ||
            !Array.isArray(input.coveredDevices)
        ) {
            throw new RelayError(400, "Invalid delivery session control", {
                error: "malformed",
            });
        }
        return {
            version: 1,
            type: "message",
            epoch: decimalUint64(input.epoch, "delivery session epoch"),
            content: input.content,
            coveredDevices: input.coveredDevices.map((device) =>
                bytesValue(device, "covered session device", IDENTITY_BYTES),
            ),
        };
    }
    if (input.type !== "create" && input.type !== "commit") {
        throw new RelayError(400, "Invalid delivery session control", { error: "malformed" });
    }
    exactKeys(
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
        !Array.isArray(input.coveredDevices)
    ) {
        throw new RelayError(400, "Invalid delivery session control", { error: "malformed" });
    }
    const common = {
        version: 1 as const,
        epoch: decimalUint64(input.epoch, "delivery session epoch"),
        members: input.members.map((member) =>
            bytesValue(member, "delivery session member", IDENTITY_BYTES),
        ),
        roles: parseSessionRoles(input.roles),
        coveredDevices: input.coveredDevices.map((device) =>
            bytesValue(device, "covered session device", IDENTITY_BYTES),
        ),
    };
    if (input.type === "create") return { ...common, type: "create" };
    if (!Array.isArray(input.changes)) {
        throw new RelayError(400, "Invalid delivery session changes", { error: "malformed" });
    }
    return {
        ...common,
        type: "commit",
        changes: input.changes.map((value2) => {
            const change = objectValue(value2, "delivery session change");
            exactKeys(change, ["type", "accountKey", "deviceKey"], "delivery session change");
            if (change.type !== "add" && change.type !== "remove") {
                throw new RelayError(400, "Invalid delivery session change", {
                    error: "malformed",
                });
            }
            return {
                type: change.type,
                accountKey: bytesValue(
                    change.accountKey,
                    "delivery session change account",
                    IDENTITY_BYTES,
                ),
                deviceKey: bytesValue(
                    change.deviceKey,
                    "delivery session change device",
                    IDENTITY_BYTES,
                ),
            };
        }),
    };
}

function validateCanonicalIdentities(values: readonly Uint8Array[], name: string): void {
    if (values.length > MAXIMUM_SESSION_IDENTITIES) {
        throw new RelayError(413, `${name} exceeds relay limit`, { error: "limit" });
    }
    let previous: Uint8Array | undefined;
    for (const value of values) {
        validateIdentity(value, name);
        if (previous !== undefined && compareBytes(previous, value) >= 0) {
            throw new RelayError(400, `${name} must be sorted and unique`, {
                error: "malformed",
            });
        }
        previous = value;
    }
}

function validateSessionControl(control: DeliverySessionControl): void {
    if (control.version !== 1 || control.epoch < 0n || control.epoch > MAXIMUM_UINT64) {
        throw new RelayError(400, "Invalid delivery session control", { error: "malformed" });
    }
    validateCanonicalIdentities(control.coveredDevices, "covered session devices");
    if (control.type === "message") return;
    validateCanonicalIdentities(control.members, "delivery session members");
    validateIdentity(control.roles.owner, "delivery session owner");
    validateCanonicalIdentities(control.roles.admins, "delivery session admins");
    if (
        control.roles.admins.some((admin) => equalBytes(admin, control.roles.owner)) ||
        typeof control.roles.adminsAssignAdmins !== "boolean" ||
        typeof control.roles.anyoneCanAddMembers !== "boolean" ||
        (control.roles.sendPolicy !== "everyone" && control.roles.sendPolicy !== "admins")
    ) {
        throw new RelayError(400, "Invalid delivery session roles", { error: "malformed" });
    }
    if (control.type === "commit") {
        if (control.changes.length > MAXIMUM_SESSION_IDENTITIES * 2) {
            throw new RelayError(413, "Delivery session changes exceed relay limit", {
                error: "limit",
            });
        }
        let previous: (typeof control.changes)[number] | undefined;
        for (const change of control.changes) {
            validateIdentity(change.accountKey, "delivery session change account");
            validateIdentity(change.deviceKey, "delivery session change device");
            if (previous !== undefined && compareChanges(previous, change) >= 0) {
                throw new RelayError(400, "Delivery session changes must be sorted and unique", {
                    error: "malformed",
                });
            }
            previous = change;
        }
    }
}

/** Strictly decode one account-signed session-deletion request body. */
export function parseSessionDeletionRequest(value: Uint8Array): Uint8Array {
    if (!(value instanceof Uint8Array) || value.length < 1 || value.length > 1_024) {
        throw new RelayError(400, "Invalid session deletion request", { error: "malformed" });
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(textDecoder.decode(value)) as unknown;
    } catch {
        throw new RelayError(400, "Invalid session deletion request", { error: "malformed" });
    }
    const input = objectValue(parsed, "session deletion request");
    exactKeys(input, ["version", "type", "sessionId"], "session deletion request");
    if (input.version !== 1 || input.type !== "delete_session") {
        throw new RelayError(400, "Invalid session deletion request", { error: "malformed" });
    }
    return bytesValue(input.sessionId, "session deletion ID", IDENTITY_BYTES);
}

/** Strictly decode one account-signed terminal account-deletion request body. */
export function parseAccountDeletionRequest(value: Uint8Array): void {
    if (!(value instanceof Uint8Array) || value.length < 1 || value.length > 1_024) {
        throw new RelayError(400, "Invalid account deletion request", { error: "malformed" });
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(textDecoder.decode(value)) as unknown;
    } catch {
        throw new RelayError(400, "Invalid account deletion request", { error: "malformed" });
    }
    const input = objectValue(parsed, "account deletion request");
    exactKeys(input, ["version", "type"], "account deletion request");
    if (input.version !== 1 || input.type !== "delete_account") {
        throw new RelayError(400, "Invalid account deletion request", { error: "malformed" });
    }
}

function validateIdentity(value: unknown, name: string): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array) || value.length !== IDENTITY_BYTES) {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
    try {
        const point = ed25519.Point.fromBytes(value, false);
        point.assertValidity();
        const canonical = point.toBytes();
        if (
            point.isSmallOrder() ||
            !point.isTorsionFree() ||
            point.equals(ed25519.Point.ZERO) ||
            !equalBytes(canonical, value)
        ) {
            throw new Error("Invalid identity point");
        }
    } catch {
        throw new RelayError(400, `Invalid ${name}`, { error: "malformed" });
    }
}

function validateSignature(value: unknown): asserts value is Uint8Array {
    if (!(value instanceof Uint8Array) || value.length !== SIGNATURE_BYTES) {
        throw new RelayError(400, "Invalid signature", { error: "malformed" });
    }
}

/** Return whether a delivery identifier is the canonical encoding of 24 bytes. */
export function isDeliveryId(value: string): boolean {
    return isBase64Url(value, DELIVERY_ID_BYTES);
}

/** Validate one exact in-memory delivery shape without applying relay policy. */
export function validateSignedDeliveryShape(delivery: SignedDelivery): void {
    const value = objectValue(delivery, "delivery");
    exactKeys(
        value,
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
        "delivery",
    );
    if (delivery.version !== 1 || typeof delivery.id !== "string" || !isDeliveryId(delivery.id)) {
        throw new RelayError(400, "Invalid delivery", { error: "malformed" });
    }
    validateIdentity(delivery.sender, "delivery sender");
    validateIdentity(delivery.senderAccount, "delivery sender account");
    if (!Array.isArray(delivery.recipients)) {
        throw new RelayError(400, "Invalid delivery recipients", { error: "malformed" });
    }
    if (!Array.isArray(delivery.targetAccounts)) {
        throw new RelayError(400, "Invalid delivery target accounts", { error: "malformed" });
    }
    if ((delivery.ownerAccount === null) !== (delivery.sessionId === null)) {
        throw new RelayError(400, "Invalid delivery session ownership", { error: "malformed" });
    }
    if (delivery.ownerAccount !== null) validateIdentity(delivery.ownerAccount, "delivery owner");
    if (delivery.sessionId !== null && delivery.sessionId.length !== IDENTITY_BYTES) {
        throw new RelayError(400, "Invalid delivery session ID", { error: "malformed" });
    }
    if (delivery.sessionControl !== null) {
        if (
            delivery.ownerAccount === null ||
            delivery.sessionId === null ||
            delivery.recipients.length !== 0 ||
            delivery.targetAccounts.length !== 0
        ) {
            throw new RelayError(400, "Session-addressed delivery names direct recipients", {
                error: "malformed",
            });
        }
        validateSessionControl(delivery.sessionControl);
    }
    let previous: Uint8Array | undefined;
    for (const recipient of delivery.recipients) {
        validateIdentity(recipient, "delivery recipient");
        if (previous !== undefined && compareBytes(previous, recipient) >= 0) {
            throw new RelayError(400, "Delivery recipients must be sorted and unique", {
                error: "malformed",
            });
        }
        previous = recipient;
    }
    previous = undefined;
    for (const target of delivery.targetAccounts) {
        const value = objectValue(target, "delivery target account");
        exactKeys(value, ["accountKey", "rosterRevision"], "delivery target account");
        validateIdentity(target.accountKey, "delivery target account");
        if (!Number.isSafeInteger(target.rosterRevision) || target.rosterRevision < 0) {
            throw new RelayError(400, "Invalid delivery target roster revision", {
                error: "malformed",
            });
        }
        if (previous !== undefined && compareBytes(previous, target.accountKey) >= 0) {
            throw new RelayError(400, "Delivery target accounts must be sorted and unique", {
                error: "malformed",
            });
        }
        previous = target.accountKey;
    }
    if (
        !Number.isSafeInteger(delivery.createdAt) ||
        delivery.createdAt < 0 ||
        !Number.isSafeInteger(delivery.expiresAt) ||
        delivery.expiresAt < 0 ||
        !(delivery.ciphertext instanceof Uint8Array)
    ) {
        throw new RelayError(400, "Invalid delivery", { error: "malformed" });
    }
    validateSignature(delivery.signature);
}

/** Convert one exact delivery to JSON. */
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

/** Strictly decode one signed delivery. */
export function parseSignedDelivery(value: unknown): SignedDelivery {
    const input = objectValue(value, "delivery");
    exactKeys(
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
        "delivery",
    );
    if (
        input.version !== 1 ||
        typeof input.id !== "string" ||
        !isDeliveryId(input.id) ||
        !Array.isArray(input.recipients) ||
        !Array.isArray(input.targetAccounts)
    ) {
        throw new RelayError(400, "Invalid delivery", { error: "malformed" });
    }
    const delivery: SignedDelivery = {
        version: 1,
        id: input.id,
        sender: bytesValue(input.sender, "delivery sender", IDENTITY_BYTES),
        senderAccount: bytesValue(input.senderAccount, "delivery sender account", IDENTITY_BYTES),
        recipients: input.recipients.map((recipient) =>
            bytesValue(recipient, "delivery recipient", IDENTITY_BYTES),
        ),
        targetAccounts: input.targetAccounts.map((candidate) => {
            const target = objectValue(candidate, "delivery target account");
            exactKeys(target, ["accountKey", "rosterRevision"], "delivery target account");
            return {
                accountKey: bytesValue(
                    target.accountKey,
                    "delivery target account",
                    IDENTITY_BYTES,
                ),
                rosterRevision: safeInteger(
                    target.rosterRevision,
                    "delivery target roster revision",
                ),
            };
        }),
        ownerAccount:
            input.ownerAccount === null
                ? null
                : bytesValue(input.ownerAccount, "delivery owner", IDENTITY_BYTES),
        sessionId:
            input.sessionId === null
                ? null
                : bytesValue(input.sessionId, "delivery session ID", IDENTITY_BYTES),
        sessionControl: parseSessionControl(input.sessionControl),
        createdAt: safeInteger(input.createdAt, "delivery timestamp"),
        expiresAt: safeInteger(input.expiresAt, "delivery expiration"),
        ciphertext: bytesValue(input.ciphertext, "delivery ciphertext"),
        signature: bytesValue(input.signature, "delivery signature", SIGNATURE_BYTES),
    };
    validateSignedDeliveryShape(delivery);
    return delivery;
}

/** Canonical bytes covered by the delivery signature. */
export function deliverySigningBytes(delivery: SignedDelivery): Uint8Array {
    const encoded = signedDeliveryToJson(delivery);
    const { signature: _signature, ...unsigned } = encoded;
    return domainSeparated("murmur.relay.delivery.v1", unsigned);
}

/** Verify a delivery under its public sender identity. */
export function verifyDeliverySignature(delivery: SignedDelivery): boolean {
    try {
        return ed25519.verify(delivery.signature, deliverySigningBytes(delivery), delivery.sender, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

/** Hash the complete signed delivery for pending idempotency. */
export function deliveryFingerprint(delivery: SignedDelivery): Uint8Array {
    return sha256(canonicalJson(signedDeliveryToJson(delivery)));
}

function validateReadShape(read: SignedQueueRead): void {
    const value = objectValue(read, "queue read");
    exactKeys(
        value,
        ["version", "recipient", "after", "limit", "waitMilliseconds", "createdAt", "signature"],
        "queue read",
    );
    if (
        read.version !== 1 ||
        (read.after !== null && !isUuidV7(read.after)) ||
        !Number.isSafeInteger(read.limit) ||
        read.limit < 0 ||
        !Number.isSafeInteger(read.waitMilliseconds) ||
        read.waitMilliseconds < 0 ||
        !Number.isSafeInteger(read.createdAt) ||
        read.createdAt < 0
    ) {
        throw new RelayError(400, "Invalid queue read", { error: "malformed" });
    }
    validateIdentity(read.recipient, "queue recipient");
    validateSignature(read.signature);
}

/** Convert one signed queue read to JSON. */
export function signedQueueReadToJson(read: SignedQueueRead): SignedQueueReadJson {
    validateReadShape(read);
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

/** Strictly decode one signed queue read. */
export function parseSignedQueueRead(value: unknown): SignedQueueRead {
    const input = objectValue(value, "queue read");
    exactKeys(
        input,
        ["version", "recipient", "after", "limit", "waitMilliseconds", "createdAt", "signature"],
        "queue read",
    );
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid queue read", { error: "malformed" });
    }
    const read: SignedQueueRead = {
        version: 1,
        recipient: bytesValue(input.recipient, "queue recipient", IDENTITY_BYTES),
        after: input.after === null ? null : eventCursor(input.after, "queue cursor"),
        limit: safeInteger(input.limit, "queue limit"),
        waitMilliseconds: safeInteger(input.waitMilliseconds, "long-poll duration"),
        createdAt: safeInteger(input.createdAt, "queue read timestamp"),
        signature: bytesValue(input.signature, "queue read signature", SIGNATURE_BYTES),
    };
    validateReadShape(read);
    return read;
}

/** Canonical bytes covered by a queue-read signature. */
export function queueReadSigningBytes(read: SignedQueueRead): Uint8Array {
    const encoded = signedQueueReadToJson(read);
    const { signature: _signature, ...unsigned } = encoded;
    return domainSeparated("murmur.relay.queue-read.v1", unsigned);
}

/** Verify a queue read under the recipient identity. */
export function verifyQueueReadSignature(read: SignedQueueRead): boolean {
    try {
        return ed25519.verify(read.signature, queueReadSigningBytes(read), read.recipient, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

function validateAckShape(ack: SignedQueueAck): void {
    const value = objectValue(ack, "queue acknowledgement");
    exactKeys(
        value,
        ["version", "recipient", "through", "createdAt", "signature"],
        "queue acknowledgement",
    );
    if (
        ack.version !== 1 ||
        !isUuidV7(ack.through) ||
        !Number.isSafeInteger(ack.createdAt) ||
        ack.createdAt < 0
    ) {
        throw new RelayError(400, "Invalid queue acknowledgement", {
            error: "malformed",
        });
    }
    validateIdentity(ack.recipient, "queue recipient");
    validateSignature(ack.signature);
}

/** Convert one signed queue acknowledgement to JSON. */
export function signedQueueAckToJson(ack: SignedQueueAck): SignedQueueAckJson {
    validateAckShape(ack);
    return {
        version: 1,
        recipient: encodeBase64Url(ack.recipient),
        through: ack.through,
        createdAt: ack.createdAt,
        signature: encodeBase64Url(ack.signature),
    };
}

/** Strictly decode one signed queue acknowledgement. */
export function parseSignedQueueAck(value: unknown): SignedQueueAck {
    const input = objectValue(value, "queue acknowledgement");
    exactKeys(
        input,
        ["version", "recipient", "through", "createdAt", "signature"],
        "queue acknowledgement",
    );
    if (input.version !== 1) {
        throw new RelayError(400, "Invalid queue acknowledgement", {
            error: "malformed",
        });
    }
    const ack: SignedQueueAck = {
        version: 1,
        recipient: bytesValue(input.recipient, "queue recipient", IDENTITY_BYTES),
        through: eventCursor(input.through, "acknowledgement event ID"),
        createdAt: safeInteger(input.createdAt, "acknowledgement timestamp"),
        signature: bytesValue(input.signature, "acknowledgement signature", SIGNATURE_BYTES),
    };
    validateAckShape(ack);
    return ack;
}

/** Canonical bytes covered by a queue-acknowledgement signature. */
export function queueAckSigningBytes(ack: SignedQueueAck): Uint8Array {
    const encoded = signedQueueAckToJson(ack);
    const { signature: _signature, ...unsigned } = encoded;
    return domainSeparated("murmur.relay.queue-ack.v1", unsigned);
}

/** Verify a queue acknowledgement under the recipient identity. */
export function verifyQueueAckSignature(ack: SignedQueueAck): boolean {
    try {
        return ed25519.verify(ack.signature, queueAckSigningBytes(ack), ack.recipient, {
            zip215: false,
        });
    } catch {
        return false;
    }
}

function domainSeparated(domain: string, value: unknown): Uint8Array {
    const prefix = textEncoder.encode(`${domain}\0`);
    const body = canonicalJson(value);
    const result = new Uint8Array(prefix.length + body.length);
    result.set(prefix);
    result.set(body, prefix.length);
    return result;
}
