import { gcm } from "@noble/ciphers/aes";
import { randomBytes, type SealedBox } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    concatBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";

const BOOTSTRAP_KIND = 1;
const PRIVATE_KIND = 2;
const COMMIT_KIND = 3;
const PROVISIONING_KIND = 4;
const ACCOUNT_RESET_KIND = 5;
const MAXIMUM_PROVISIONING_BYTES = 256 * 1024;
const MAXIMUM_FRAME_BYTES = 70 * 1024 * 1024;
const MAXIMUM_UINT64 = 0xffff_ffff_ffff_ffffn;
const COMMIT_DOMAIN = utf8Encode("murmur/session-commit/v1");

/** MLS-protected role state carried by every Commit of a role-managed session. */
export interface SessionRoles {
    /** Owner account key; always an admin, never demoted or removed. */
    readonly owner: Uint8Array;
    /** Admin account keys, excluding the owner, in canonical base64url order. */
    readonly admins: readonly Uint8Array[];
    /** Whether an admin may grant admin to another member. */
    readonly adminsAssignAdmins: boolean;
    /** Whether any member may add a new member account. */
    readonly anyoneCanAddMembers: boolean;
}

/** MLS-authenticated session metadata shared by every current logical member. */
export interface SessionControl {
    readonly roles: SessionRoles;
    readonly privateGroupMasterSecret: Uint8Array;
}

const MAXIMUM_ROLE_ADMINS = 256;

/** Copy role state into a normalized, deduplicated, canonically ordered value. */
export function normalizeSessionRoles(roles: SessionRoles): SessionRoles {
    if (roles.owner.length !== 32) throw new Error("Invalid session owner");
    const owner = encodeBase64Url(roles.owner);
    const admins = new Map<string, Uint8Array>();
    for (const admin of roles.admins) {
        if (admin.length !== 32) throw new Error("Invalid session admin");
        const encoded = encodeBase64Url(admin);
        if (encoded !== owner) admins.set(encoded, admin.slice());
    }
    if (admins.size > MAXIMUM_ROLE_ADMINS) throw new Error("Session admin set is too large");
    return {
        owner: roles.owner.slice(),
        admins: [...admins.entries()]
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([, value]) => value),
        adminsAssignAdmins: roles.adminsAssignAdmins,
        anyoneCanAddMembers: roles.anyoneCanAddMembers,
    };
}

function rolesToJson(roles: SessionRoles): Record<string, unknown> {
    const normalized = normalizeSessionRoles(roles);
    return {
        owner: encodeBase64Url(normalized.owner),
        admins: normalized.admins.map((admin) => encodeBase64Url(admin)),
        adminsAssignAdmins: normalized.adminsAssignAdmins,
        anyoneCanAddMembers: normalized.anyoneCanAddMembers,
    };
}

function rolesFromJson(value: unknown, name: string): SessionRoles {
    const input = object(value, name);
    exact(input, ["owner", "admins", "adminsAssignAdmins", "anyoneCanAddMembers"], name);
    if (
        !Array.isArray(input.admins) ||
        input.admins.length > MAXIMUM_ROLE_ADMINS ||
        typeof input.adminsAssignAdmins !== "boolean" ||
        typeof input.anyoneCanAddMembers !== "boolean"
    ) {
        throw new Error(`Invalid ${name}`);
    }
    const owner = bytes(input.owner, 32, name);
    const admins = input.admins.map((admin) => bytes(admin, 32, name));
    if (owner.length !== 32 || admins.some((admin) => admin.length !== 32)) {
        throw new Error(`Invalid ${name}`);
    }
    const encoded = admins.map((admin) => encodeBase64Url(admin));
    const canonical = [...new Set(encoded)].sort((left, right) => left.localeCompare(right));
    if (
        encoded.length !== canonical.length ||
        encoded.some((value2, index) => value2 !== canonical[index]) ||
        encoded.includes(encodeBase64Url(owner))
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return {
        owner,
        admins,
        adminsAssignAdmins: input.adminsAssignAdmins,
        anyoneCanAddMembers: input.anyoneCanAddMembers,
    };
}

/** Encode normalized role state for durable session records. */
export function encodeSessionRoles(roles: SessionRoles): Uint8Array {
    return canonicalJsonBytes(rolesToJson(roles) as never);
}

/** Decode normalized role state from one durable session record. */
export function decodeSessionRoles(value: Uint8Array): SessionRoles {
    return rolesFromJson(parseJson(value, "session roles"), "session roles");
}

/** Structural equality over normalized role state. */
export function sessionRolesEqual(left: SessionRoles, right: SessionRoles): boolean {
    return (
        equalBytes(left.owner, right.owner) &&
        left.admins.length === right.admins.length &&
        left.admins.every((admin, index) => equalBytes(admin, right.admins[index]!)) &&
        left.adminsAssignAdmins === right.adminsAssignAdmins &&
        left.anyoneCanAddMembers === right.anyoneCanAddMembers
    );
}

export interface BootstrapFrame {
    readonly version: 1;
    readonly inviter: Uint8Array;
    readonly groupId: Uint8Array;
    readonly descriptor: Uint8Array;
    readonly welcome: Uint8Array;
    readonly tree: Uint8Array;
    readonly confirmationTag: Uint8Array;
    readonly commit: Uint8Array;
    readonly keyPackageReference: Uint8Array;
    readonly roles: SessionRoles;
    readonly privateGroupMasterSecret: Uint8Array;
}

export type PrivateSessionFrame =
    | { readonly version: 1; readonly type: "application"; readonly bytes: Uint8Array }
    | { readonly version: 1; readonly type: "leave" }
    | { readonly version: 1; readonly type: "welcome_complete" }
    | {
          readonly version: 1;
          readonly type: "account_roster";
          readonly roster: Uint8Array;
          readonly keyPackage?: Uint8Array;
      };

export interface CommitFrame {
    readonly version: 1;
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly commit: Uint8Array;
    readonly roles: SessionRoles;
    readonly privateGroupMasterSecret: Uint8Array;
}

export type SessionCiphertext =
    | { readonly kind: "bootstrap"; readonly box: SealedBox }
    | { readonly kind: "private"; readonly message: Uint8Array }
    | { readonly kind: "provisioning"; readonly envelope: Uint8Array }
    | { readonly kind: "account_reset"; readonly box: SealedBox }
    | {
          readonly kind: "commit";
          readonly groupId: Uint8Array;
          readonly epoch: bigint;
          readonly nonce: Uint8Array;
          readonly ciphertext: Uint8Array;
      };

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

function bytes(value: unknown, maximum: number, name: string): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((maximum * 4) / 3)) {
        throw new Error(`Invalid ${name}`);
    }
    const result = decodeBase64Url(value);
    if (result.length > maximum || encodeBase64Url(result) !== value) {
        throw new Error(`Invalid ${name}`);
    }
    return result;
}

function parseJson(value: Uint8Array, name: string): Record<string, unknown> {
    if (value.length < 1 || value.length > MAXIMUM_FRAME_BYTES) {
        throw new Error(`Invalid ${name}`);
    }
    try {
        return object(JSON.parse(utf8Decode(value)) as unknown, name);
    } catch {
        throw new Error(`Invalid ${name}`);
    }
}

function decimalUint64(value: unknown, name: string): bigint {
    if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const decoded = BigInt(value);
    if (decoded > MAXIMUM_UINT64) throw new Error(`Invalid ${name}`);
    return decoded;
}

function prefixed(kind: number, bytesValue: Uint8Array): Uint8Array {
    return concatBytes(new Uint8Array([kind]), bytesValue);
}

export function encodeBootstrapCiphertext(box: SealedBox): Uint8Array {
    return prefixed(
        BOOTSTRAP_KIND,
        canonicalJsonBytes({
            version: 1,
            ephemeralPublicKey: encodeBase64Url(box.ephemeralPublicKey),
            nonce: encodeBase64Url(box.nonce),
            ciphertext: encodeBase64Url(box.ciphertext),
        }),
    );
}

/** Frame one recipient-sealed account reset announcement independent of MLS state. */
export function encodeAccountResetCiphertext(box: SealedBox): Uint8Array {
    return prefixed(
        ACCOUNT_RESET_KIND,
        canonicalJsonBytes({
            version: 1,
            ephemeralPublicKey: encodeBase64Url(box.ephemeralPublicKey),
            nonce: encodeBase64Url(box.nonce),
            ciphertext: encodeBase64Url(box.ciphertext),
        }),
    );
}

/** Frame one already-encrypted provisioning envelope for inbox delivery. */
export function encodeProvisioningCiphertext(envelope: Uint8Array): Uint8Array {
    if (envelope.length < 1 || envelope.length > MAXIMUM_PROVISIONING_BYTES) {
        throw new Error("Invalid provisioning envelope delivery");
    }
    return prefixed(PROVISIONING_KIND, envelope);
}

export function encodePrivateCiphertext(message: Uint8Array): Uint8Array {
    if (message.length < 1 || message.length > MAXIMUM_FRAME_BYTES) {
        throw new Error("Invalid MLS private delivery");
    }
    return prefixed(PRIVATE_KIND, message);
}

function commitAad(groupId: Uint8Array, epoch: bigint): Uint8Array {
    return concatBytes(
        COMMIT_DOMAIN,
        canonicalJsonBytes({
            groupId: encodeBase64Url(groupId),
            epoch: epoch.toString(),
        }),
    );
}

export function sealCommitCiphertext(key: Uint8Array, frame: CommitFrame): Uint8Array {
    if (key.length !== 32) throw new Error("Invalid Commit frame key");
    if (
        frame.epoch < 0n ||
        frame.epoch > MAXIMUM_UINT64 ||
        frame.privateGroupMasterSecret.length !== 32
    ) {
        throw new Error("Invalid Commit frame");
    }
    const nonce = randomBytes(12);
    const plaintext = canonicalJsonBytes({
        version: 1,
        groupId: encodeBase64Url(frame.groupId),
        epoch: frame.epoch.toString(),
        commit: encodeBase64Url(frame.commit),
        roles: rolesToJson(frame.roles),
        privateGroupMasterSecret: encodeBase64Url(frame.privateGroupMasterSecret),
    } as never);
    try {
        const ciphertext = gcm(key, nonce, commitAad(frame.groupId, frame.epoch)).encrypt(
            plaintext,
        );
        return prefixed(
            COMMIT_KIND,
            canonicalJsonBytes({
                version: 1,
                groupId: encodeBase64Url(frame.groupId),
                epoch: frame.epoch.toString(),
                nonce: encodeBase64Url(nonce),
                ciphertext: encodeBase64Url(ciphertext),
            }),
        );
    } finally {
        zeroBytes(plaintext);
    }
}

export function parseSessionCiphertext(value: Uint8Array): SessionCiphertext {
    if (value.length < 2 || value.length > MAXIMUM_FRAME_BYTES) {
        throw new Error("Invalid session ciphertext");
    }
    const kind = value[0];
    const body = value.slice(1);
    if (kind === PRIVATE_KIND) return { kind: "private", message: body };
    if (kind === PROVISIONING_KIND) {
        if (body.length > MAXIMUM_PROVISIONING_BYTES) {
            throw new Error("Invalid provisioning envelope delivery");
        }
        return { kind: "provisioning", envelope: body };
    }
    const input = parseJson(body, "session ciphertext");
    if (kind === BOOTSTRAP_KIND || kind === ACCOUNT_RESET_KIND) {
        exact(
            input,
            ["version", "ephemeralPublicKey", "nonce", "ciphertext"],
            "bootstrap ciphertext",
        );
        if (input.version !== 1) throw new Error("Invalid bootstrap ciphertext");
        return {
            kind: kind === BOOTSTRAP_KIND ? "bootstrap" : "account_reset",
            box: {
                ephemeralPublicKey: bytes(input.ephemeralPublicKey, 32, "box key"),
                nonce: bytes(input.nonce, 12, "box nonce"),
                ciphertext: bytes(input.ciphertext, 64 * 1024 * 1024, "box ciphertext"),
            },
        };
    }
    if (kind !== COMMIT_KIND) throw new Error("Unknown session ciphertext kind");
    exact(input, ["version", "groupId", "epoch", "nonce", "ciphertext"], "Commit ciphertext");
    if (input.version !== 1) throw new Error("Invalid Commit ciphertext");
    const epoch = decimalUint64(input.epoch, "Commit ciphertext");
    return {
        kind: "commit",
        groupId: bytes(input.groupId, 255, "Commit group ID"),
        epoch,
        nonce: bytes(input.nonce, 12, "Commit nonce"),
        ciphertext: bytes(input.ciphertext, 64 * 1024 * 1024, "Commit ciphertext"),
    };
}

export function openCommitCiphertext(
    key: Uint8Array,
    wire: Extract<SessionCiphertext, { kind: "commit" }>,
): CommitFrame {
    if (key.length !== 32) throw new Error("Invalid Commit frame key");
    const plaintext = gcm(key, wire.nonce, commitAad(wire.groupId, wire.epoch)).decrypt(
        wire.ciphertext,
    );
    try {
        const input = parseJson(plaintext, "Commit frame");
        exact(
            input,
            ["version", "groupId", "epoch", "commit", "roles", "privateGroupMasterSecret"],
            "Commit frame",
        );
        if (input.version !== 1) throw new Error("Invalid Commit frame");
        const frame: CommitFrame = {
            version: 1,
            groupId: bytes(input.groupId, 255, "Commit group ID"),
            epoch: decimalUint64(input.epoch, "Commit frame"),
            commit: bytes(input.commit, 64 * 1024 * 1024, "Commit"),
            roles: rolesFromJson(input.roles, "Commit roles"),
            privateGroupMasterSecret: bytes(
                input.privateGroupMasterSecret,
                32,
                "Commit private-group master secret",
            ),
        };
        if (
            !equalBytes(frame.groupId, wire.groupId) ||
            frame.epoch !== wire.epoch ||
            frame.privateGroupMasterSecret.length !== 32
        ) {
            zeroBytes(frame.privateGroupMasterSecret);
            throw new Error("Commit frame header mismatch");
        }
        return frame;
    } finally {
        zeroBytes(plaintext);
    }
}

export function encodeBootstrapFrame(frame: BootstrapFrame): Uint8Array {
    if (frame.privateGroupMasterSecret.length !== 32) {
        throw new Error("Invalid bootstrap frame");
    }
    return canonicalJsonBytes({
        version: 1,
        inviter: encodeBase64Url(frame.inviter),
        groupId: encodeBase64Url(frame.groupId),
        descriptor: encodeBase64Url(frame.descriptor),
        welcome: encodeBase64Url(frame.welcome),
        tree: encodeBase64Url(frame.tree),
        confirmationTag: encodeBase64Url(frame.confirmationTag),
        commit: encodeBase64Url(frame.commit),
        keyPackageReference: encodeBase64Url(frame.keyPackageReference),
        roles: rolesToJson(frame.roles),
        privateGroupMasterSecret: encodeBase64Url(frame.privateGroupMasterSecret),
    } as never);
}

export function decodeBootstrapFrame(value: Uint8Array): BootstrapFrame {
    const input = parseJson(value, "bootstrap frame");
    exact(
        input,
        [
            "version",
            "inviter",
            "groupId",
            "descriptor",
            "welcome",
            "tree",
            "confirmationTag",
            "commit",
            "keyPackageReference",
            "roles",
            "privateGroupMasterSecret",
        ],
        "bootstrap frame",
    );
    if (input.version !== 1) throw new Error("Invalid bootstrap frame");
    const roles = rolesFromJson(input.roles, "bootstrap roles");
    const common = {
        version: 1 as const,
        inviter: bytes(input.inviter, 32, "bootstrap inviter"),
        groupId: bytes(input.groupId, 255, "bootstrap group ID"),
        descriptor: bytes(input.descriptor, 1024 * 1024, "bootstrap descriptor"),
        welcome: bytes(input.welcome, 64 * 1024 * 1024, "MLS Welcome"),
        tree: bytes(input.tree, 64 * 1024 * 1024, "MLS tree"),
        confirmationTag: bytes(input.confirmationTag, 32, "Commit confirmation tag"),
        commit: bytes(input.commit, 64 * 1024 * 1024, "bootstrap Commit"),
        keyPackageReference: bytes(input.keyPackageReference, 32, "KeyPackage reference"),
        roles,
    };
    const privateGroupMasterSecret = bytes(
        input.privateGroupMasterSecret,
        32,
        "bootstrap private-group master secret",
    );
    if (privateGroupMasterSecret.length !== 32) {
        zeroBytes(privateGroupMasterSecret);
        throw new Error("Invalid bootstrap frame");
    }
    return {
        ...common,
        privateGroupMasterSecret,
    };
}

/** Encode roles and the stable private-group secret as authenticated Commit control. */
export function encodeSessionControl(control: SessionControl): Uint8Array {
    if (control.privateGroupMasterSecret.length !== 32) {
        throw new Error("Invalid session control");
    }
    return canonicalJsonBytes({
        version: 3,
        type: "session",
        roles: rolesToJson(control.roles),
        privateGroupMasterSecret: encodeBase64Url(control.privateGroupMasterSecret),
    } as never);
}

/** Decode roles and the stable private-group secret from Commit authenticated data. */
export function decodeSessionControl(value: Uint8Array): SessionControl {
    const input = parseJson(value, "session control");
    if (input.version === 3 && input.type === "session") {
        exact(input, ["version", "type", "roles", "privateGroupMasterSecret"], "session control");
        const roles = rolesFromJson(input.roles, "session control roles");
        const privateGroupMasterSecret = bytes(
            input.privateGroupMasterSecret,
            32,
            "session control private-group master secret",
        );
        if (privateGroupMasterSecret.length !== 32) {
            zeroBytes(privateGroupMasterSecret);
            throw new Error("Invalid session control");
        }
        return {
            roles,
            privateGroupMasterSecret,
        };
    }
    throw new Error("Invalid session control");
}

export function encodePrivateFrame(frame: PrivateSessionFrame): Uint8Array {
    if (frame.type === "application") {
        return canonicalJsonBytes({
            version: 1,
            type: frame.type,
            bytes: encodeBase64Url(frame.bytes),
        });
    }
    if (frame.type === "account_roster") {
        return canonicalJsonBytes({
            version: 1,
            type: frame.type,
            roster: encodeBase64Url(frame.roster),
            keyPackage: frame.keyPackage === undefined ? null : encodeBase64Url(frame.keyPackage),
        });
    }
    if (frame.type === "leave") {
        return canonicalJsonBytes({ version: 1, type: frame.type });
    }
    if (frame.type === "welcome_complete") {
        return canonicalJsonBytes({ version: 1, type: frame.type });
    }
    throw new Error("Unsupported private session frame");
}

export function decodePrivateFrame(value: Uint8Array): PrivateSessionFrame {
    const input = parseJson(value, "private session frame");
    if (input.version !== 1 || typeof input.type !== "string") {
        throw new Error("Invalid private session frame");
    }
    if (input.type === "application") {
        exact(input, ["version", "type", "bytes"], "application frame");
        return {
            version: 1,
            type: "application",
            bytes: bytes(input.bytes, 1024 * 1024, "application bytes"),
        };
    }
    if (input.type === "account_roster") {
        exact(input, ["version", "type", "roster", "keyPackage"], "account roster control");
        if (input.keyPackage !== null && typeof input.keyPackage !== "string") {
            throw new Error("Invalid account roster control");
        }
        return {
            version: 1,
            type: "account_roster",
            roster: bytes(input.roster, 64 * 1024, "account roster"),
            ...(input.keyPackage === null
                ? {}
                : {
                      keyPackage: bytes(input.keyPackage, 1024 * 1024, "account device KeyPackage"),
                  }),
        };
    }
    if (input.type === "leave") {
        exact(input, ["version", "type"], "leave control");
        return { version: 1, type: "leave" };
    }
    if (input.type === "welcome_complete") {
        exact(input, ["version", "type"], "Welcome-complete control");
        return { version: 1, type: "welcome_complete" };
    }
    throw new Error("Unsupported private session frame");
}
