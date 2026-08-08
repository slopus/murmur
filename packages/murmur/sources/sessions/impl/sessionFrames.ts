import { gcm } from "@noble/ciphers/aes";
import { randomBytes, type SealedBox } from "../../crypto/index.js";
import type { MlsKeyPackage } from "../../mls/index.js";
import { decodeMlsKeyPackage, encodeMlsKeyPackage } from "../../mls/index.js";
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
const MAXIMUM_FRAME_BYTES = 70 * 1024 * 1024;
const COMMIT_DOMAIN = utf8Encode("murmur/session-commit/v1");

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
    readonly committer: Uint8Array;
}

export type PrivateSessionFrame =
    | { readonly version: 1; readonly type: "application"; readonly bytes: Uint8Array }
    | {
          readonly version: 1;
          readonly type: "proposal_add";
          readonly keyPackage: MlsKeyPackage;
      }
    | {
          readonly version: 1;
          readonly type: "proposal_remove";
          readonly identity: Uint8Array;
      };

export interface StoredSessionProposal {
    readonly proposer: Uint8Array;
    readonly frame: Exclude<PrivateSessionFrame, { readonly type: "application" }>;
}

export interface CommitFrame {
    readonly version: 1;
    readonly groupId: Uint8Array;
    readonly epoch: bigint;
    readonly commit: Uint8Array;
    readonly nextCommitter: Uint8Array;
}

export type SessionCiphertext =
    | { readonly kind: "bootstrap"; readonly box: SealedBox }
    | { readonly kind: "private"; readonly message: Uint8Array }
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
    if (key.length !== 32 || frame.nextCommitter.length !== 32) {
        throw new Error("Invalid Commit frame key or committer");
    }
    const nonce = randomBytes(12);
    const plaintext = canonicalJsonBytes({
        version: 1,
        groupId: encodeBase64Url(frame.groupId),
        epoch: frame.epoch.toString(),
        commit: encodeBase64Url(frame.commit),
        nextCommitter: encodeBase64Url(frame.nextCommitter),
    });
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
    const input = parseJson(body, "session ciphertext");
    if (kind === BOOTSTRAP_KIND) {
        exact(
            input,
            ["version", "ephemeralPublicKey", "nonce", "ciphertext"],
            "bootstrap ciphertext",
        );
        if (input.version !== 1) throw new Error("Invalid bootstrap ciphertext");
        return {
            kind: "bootstrap",
            box: {
                ephemeralPublicKey: bytes(input.ephemeralPublicKey, 32, "box key"),
                nonce: bytes(input.nonce, 12, "box nonce"),
                ciphertext: bytes(input.ciphertext, 64 * 1024 * 1024, "box ciphertext"),
            },
        };
    }
    if (kind !== COMMIT_KIND) throw new Error("Unknown session ciphertext kind");
    exact(input, ["version", "groupId", "epoch", "nonce", "ciphertext"], "Commit ciphertext");
    if (
        input.version !== 1 ||
        typeof input.epoch !== "string" ||
        !/^(0|[1-9]\d*)$/.test(input.epoch)
    ) {
        throw new Error("Invalid Commit ciphertext");
    }
    return {
        kind: "commit",
        groupId: bytes(input.groupId, 255, "Commit group ID"),
        epoch: BigInt(input.epoch),
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
        exact(input, ["version", "groupId", "epoch", "commit", "nextCommitter"], "Commit frame");
        if (
            input.version !== 1 ||
            typeof input.epoch !== "string" ||
            !/^(0|[1-9]\d*)$/.test(input.epoch)
        ) {
            throw new Error("Invalid Commit frame");
        }
        const frame: CommitFrame = {
            version: 1,
            groupId: bytes(input.groupId, 255, "Commit group ID"),
            epoch: BigInt(input.epoch),
            commit: bytes(input.commit, 64 * 1024 * 1024, "Commit"),
            nextCommitter: bytes(input.nextCommitter, 32, "next committer"),
        };
        if (!equalBytes(frame.groupId, wire.groupId) || frame.epoch !== wire.epoch) {
            throw new Error("Commit frame header mismatch");
        }
        return frame;
    } finally {
        zeroBytes(plaintext);
    }
}

export function encodeBootstrapFrame(frame: BootstrapFrame): Uint8Array {
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
        committer: encodeBase64Url(frame.committer),
    });
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
            "committer",
        ],
        "bootstrap frame",
    );
    if (input.version !== 1) throw new Error("Invalid bootstrap frame");
    return {
        version: 1,
        inviter: bytes(input.inviter, 32, "bootstrap inviter"),
        groupId: bytes(input.groupId, 255, "bootstrap group ID"),
        descriptor: bytes(input.descriptor, 1024 * 1024, "bootstrap descriptor"),
        welcome: bytes(input.welcome, 64 * 1024 * 1024, "MLS Welcome"),
        tree: bytes(input.tree, 64 * 1024 * 1024, "MLS tree"),
        confirmationTag: bytes(input.confirmationTag, 32, "Commit confirmation tag"),
        commit: bytes(input.commit, 64 * 1024 * 1024, "bootstrap Commit"),
        keyPackageReference: bytes(input.keyPackageReference, 32, "KeyPackage reference"),
        committer: bytes(input.committer, 32, "bootstrap committer"),
    };
}

export function encodeCommitterControl(nextCommitter: Uint8Array): Uint8Array {
    if (nextCommitter.length !== 32) throw new Error("Invalid next committer");
    return canonicalJsonBytes({
        version: 1,
        type: "committer",
        nextCommitter: encodeBase64Url(nextCommitter),
    });
}

export function decodeCommitterControl(value: Uint8Array): Uint8Array {
    const input = parseJson(value, "committer control");
    exact(input, ["version", "type", "nextCommitter"], "committer control");
    if (input.version !== 1 || input.type !== "committer") {
        throw new Error("Invalid committer control");
    }
    return bytes(input.nextCommitter, 32, "next committer");
}

export function encodePrivateFrame(frame: PrivateSessionFrame): Uint8Array {
    if (frame.type === "application") {
        return canonicalJsonBytes({
            version: 1,
            type: frame.type,
            bytes: encodeBase64Url(frame.bytes),
        });
    }
    if (frame.type === "proposal_add") {
        return canonicalJsonBytes({
            version: 1,
            type: frame.type,
            keyPackage: encodeBase64Url(encodeMlsKeyPackage(frame.keyPackage)),
        });
    }
    return canonicalJsonBytes({
        version: 1,
        type: frame.type,
        identity: encodeBase64Url(frame.identity),
    });
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
    if (input.type === "proposal_add") {
        exact(input, ["version", "type", "keyPackage"], "Add proposal");
        return {
            version: 1,
            type: "proposal_add",
            keyPackage: decodeMlsKeyPackage(bytes(input.keyPackage, 1024 * 1024, "KeyPackage")),
        };
    }
    if (input.type === "proposal_remove") {
        exact(input, ["version", "type", "identity"], "Remove proposal");
        return {
            version: 1,
            type: "proposal_remove",
            identity: bytes(input.identity, 32, "removed identity"),
        };
    }
    throw new Error("Unsupported private session frame");
}

export function encodeStoredProposal(value: StoredSessionProposal): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        proposer: encodeBase64Url(value.proposer),
        frame: encodeBase64Url(encodePrivateFrame(value.frame)),
    });
}

export function decodeStoredProposal(value: Uint8Array): StoredSessionProposal {
    const input = parseJson(value, "stored proposal");
    exact(input, ["version", "proposer", "frame"], "stored proposal");
    if (input.version !== 1) throw new Error("Invalid stored proposal");
    const frame = decodePrivateFrame(bytes(input.frame, 1024 * 1024, "stored proposal frame"));
    if (frame.type === "application") throw new Error("Invalid stored proposal");
    return {
        proposer: bytes(input.proposer, 32, "proposal sender"),
        frame,
    };
}
