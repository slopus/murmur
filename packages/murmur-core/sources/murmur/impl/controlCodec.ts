import type { IdentityProfile } from "../../identity/index.js";
import { decodeProfilePayload, encodeProfilePayload } from "../../identity/impl/profileCodec.js";
import { decodeBase64Url, encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

const MAXIMUM_CONTROL_FRAME_BYTES = 1024 * 1024;
const MAXIMUM_DESCRIPTOR_BYTES = 256 * 1024;
const MAXIMUM_MLS_MATERIAL_BYTES = 768 * 1024;

export type FriendControlFrame =
    | { readonly type: "profile-update"; readonly profile: IdentityProfile }
    | { readonly type: "friendship-ended"; readonly requestId: string }
    | {
          readonly type: "key-package-announce";
          readonly reference: Uint8Array;
          readonly keyPackage: Uint8Array;
      }
    | { readonly type: "key-package-request" }
    | {
          readonly type: "group-invitation";
          readonly groupId: Uint8Array;
          readonly descriptor: Uint8Array;
          readonly descriptorNonce: Uint8Array;
          readonly descriptorBinding: Uint8Array;
          readonly topicSecret: Uint8Array;
          readonly keyPackageReference: Uint8Array;
          readonly welcome: Uint8Array;
          readonly tree: Uint8Array;
          readonly commitSequence: bigint;
      };

function nullable(value: Uint8Array | undefined): string | null {
    return value === undefined ? null : encodeBase64Url(value);
}

/** Encode one strict versioned friend-control frame. */
export function encodeFriendControlFrame(frame: FriendControlFrame): Uint8Array {
    let profile: Uint8Array | undefined;
    try {
        profile = frame.type === "profile-update" ? encodeProfilePayload(frame.profile) : undefined;
        const encoded = utf8Encode(
            JSON.stringify({
                version: 1,
                type: frame.type,
                profile: nullable(profile),
                requestId: frame.type === "friendship-ended" ? frame.requestId : null,
                reference:
                    frame.type === "key-package-announce" ? encodeBase64Url(frame.reference) : null,
                keyPackage:
                    frame.type === "key-package-announce"
                        ? encodeBase64Url(frame.keyPackage)
                        : null,
                groupId: frame.type === "group-invitation" ? encodeBase64Url(frame.groupId) : null,
                descriptor:
                    frame.type === "group-invitation" ? encodeBase64Url(frame.descriptor) : null,
                descriptorNonce:
                    frame.type === "group-invitation"
                        ? encodeBase64Url(frame.descriptorNonce)
                        : null,
                descriptorBinding:
                    frame.type === "group-invitation"
                        ? encodeBase64Url(frame.descriptorBinding)
                        : null,
                topicSecret:
                    frame.type === "group-invitation" ? encodeBase64Url(frame.topicSecret) : null,
                keyPackageReference:
                    frame.type === "group-invitation"
                        ? encodeBase64Url(frame.keyPackageReference)
                        : null,
                welcome: frame.type === "group-invitation" ? encodeBase64Url(frame.welcome) : null,
                tree: frame.type === "group-invitation" ? encodeBase64Url(frame.tree) : null,
                commitSequence:
                    frame.type === "group-invitation" ? frame.commitSequence.toString() : null,
            }),
        );
        if (encoded.length > MAXIMUM_CONTROL_FRAME_BYTES) {
            throw new Error("Friend-control frame is too large");
        }
        return encoded;
    } finally {
        profile?.fill(0);
    }
}

function object(value: unknown): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("Invalid friend-control frame");
    }
    const result = value as Record<string, unknown>;
    const fields = [
        "version",
        "type",
        "profile",
        "requestId",
        "reference",
        "keyPackage",
        "groupId",
        "descriptor",
        "descriptorNonce",
        "descriptorBinding",
        "topicSecret",
        "keyPackageReference",
        "welcome",
        "tree",
        "commitSequence",
    ];
    if (
        Object.keys(result).length !== fields.length ||
        Object.keys(result).some((key) => !fields.includes(key))
    ) {
        throw new Error("Invalid friend-control frame");
    }
    return result;
}

function bytes(value: unknown, maximum: number, exact?: number): Uint8Array {
    if (typeof value !== "string" || value.length > Math.ceil((maximum * 4) / 3)) {
        throw new Error("Invalid friend-control bytes");
    }
    const result = decodeBase64Url(value);
    if (
        result.length > maximum ||
        (exact !== undefined && result.length !== exact) ||
        encodeBase64Url(result) !== value
    ) {
        throw new Error("Invalid friend-control bytes");
    }
    return result;
}

function allNull(value: Record<string, unknown>, except: readonly string[]): boolean {
    return Object.entries(value).every(
        ([key, entry]) =>
            key === "version" || key === "type" || except.includes(key) || entry === null,
    );
}

/** Decode one strict bounded friend-control frame. */
export function decodeFriendControlFrame(encoded: Uint8Array): FriendControlFrame {
    if (encoded.length > MAXIMUM_CONTROL_FRAME_BYTES) {
        throw new Error("Friend-control frame is too large");
    }
    const value = object(JSON.parse(utf8Decode(encoded)) as unknown);
    if (value.version !== 1 || typeof value.type !== "string") {
        throw new Error("Invalid friend-control frame");
    }
    if (value.type === "profile-update" && allNull(value, ["profile"])) {
        const profileBytes = bytes(value.profile, MAXIMUM_DESCRIPTOR_BYTES);
        try {
            return { type: "profile-update", profile: decodeProfilePayload(profileBytes) };
        } finally {
            profileBytes.fill(0);
        }
    }
    if (
        value.type === "friendship-ended" &&
        allNull(value, ["requestId"]) &&
        typeof value.requestId === "string" &&
        value.requestId.length === 32
    ) {
        bytes(value.requestId, 24, 24);
        return { type: "friendship-ended", requestId: value.requestId };
    }
    if (value.type === "key-package-announce" && allNull(value, ["reference", "keyPackage"])) {
        return {
            type: "key-package-announce",
            reference: bytes(value.reference, 32, 32),
            keyPackage: bytes(value.keyPackage, MAXIMUM_MLS_MATERIAL_BYTES),
        };
    }
    if (value.type === "key-package-request" && allNull(value, [])) {
        return { type: "key-package-request" };
    }
    if (
        value.type === "group-invitation" &&
        allNull(value, [
            "groupId",
            "descriptor",
            "descriptorNonce",
            "descriptorBinding",
            "topicSecret",
            "keyPackageReference",
            "welcome",
            "tree",
            "commitSequence",
        ]) &&
        typeof value.commitSequence === "string" &&
        /^[1-9]\d*$/.test(value.commitSequence)
    ) {
        const commitSequence = BigInt(value.commitSequence);
        if (commitSequence > 0xffff_ffff_ffff_ffffn) {
            throw new Error("Invalid invitation Commit sequence");
        }
        return {
            type: "group-invitation",
            groupId: bytes(value.groupId, 32, 32),
            descriptor: bytes(value.descriptor, MAXIMUM_DESCRIPTOR_BYTES),
            descriptorNonce: bytes(value.descriptorNonce, 32, 32),
            descriptorBinding: bytes(value.descriptorBinding, 32, 32),
            topicSecret: bytes(value.topicSecret, 32, 32),
            keyPackageReference: bytes(value.keyPackageReference, 32, 32),
            welcome: bytes(value.welcome, MAXIMUM_MLS_MATERIAL_BYTES),
            tree: bytes(value.tree, MAXIMUM_MLS_MATERIAL_BYTES),
            commitSequence,
        };
    }
    throw new Error("Unsupported friend-control frame");
}
