import type { IdentityProfile } from "../../identity/index.js";
import { decodeProfilePayload, encodeProfilePayload } from "../../identity/impl/profileCodec.js";
import {
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";

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
    | {
          readonly type: "key-package-request";
          readonly consumedReferences: readonly Uint8Array[];
      }
    | {
          readonly type: "key-package-consumed-ack";
          readonly consumedReferences: readonly Uint8Array[];
      }
    | {
          readonly type: "key-package-retire";
          readonly consumedReferences: readonly Uint8Array[];
      }
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
          readonly commitEventId: string;
          readonly commitFingerprint: Uint8Array;
      };

/** Zero every byte array owned by one decoded friend-control frame. */
export function destroyFriendControlFrame(frame: FriendControlFrame | undefined): void {
    if (frame === undefined) {
        return;
    }
    if (frame.type === "profile-update") {
        frame.profile.avatar?.fill(0);
        return;
    }
    if (frame.type === "key-package-announce") {
        zeroBytes(frame.reference);
        zeroBytes(frame.keyPackage);
        return;
    }
    if (
        frame.type === "key-package-request" ||
        frame.type === "key-package-consumed-ack" ||
        frame.type === "key-package-retire"
    ) {
        for (const reference of frame.consumedReferences) {
            zeroBytes(reference);
        }
        return;
    }
    if (frame.type === "group-invitation") {
        zeroBytes(frame.groupId);
        zeroBytes(frame.descriptor);
        zeroBytes(frame.descriptorNonce);
        zeroBytes(frame.descriptorBinding);
        zeroBytes(frame.topicSecret);
        zeroBytes(frame.keyPackageReference);
        zeroBytes(frame.welcome);
        zeroBytes(frame.tree);
        zeroBytes(frame.commitFingerprint);
    }
}

function nullable(value: Uint8Array | undefined): string | null {
    return value === undefined ? null : encodeBase64Url(value);
}

/** Encode one strict versioned friend-control frame. */
export function encodeFriendControlFrame(frame: FriendControlFrame): Uint8Array {
    let profile: Uint8Array | undefined;
    try {
        if (
            (frame.type === "key-package-request" ||
                frame.type === "key-package-consumed-ack" ||
                frame.type === "key-package-retire") &&
            (frame.consumedReferences.length > 64 ||
                new Set(frame.consumedReferences.map(encodeBase64Url)).size !==
                    frame.consumedReferences.length)
        ) {
            throw new Error("Invalid consumed KeyPackage references");
        }
        if (
            frame.type === "group-invitation" &&
            encodeBase64Url(bytes(frame.commitEventId, 32, 32)) !== frame.commitEventId
        ) {
            throw new Error("Invalid invitation Commit event ID");
        }
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
                consumedReferences:
                    frame.type === "key-package-request" ||
                    frame.type === "key-package-consumed-ack" ||
                    frame.type === "key-package-retire"
                        ? frame.consumedReferences.map(encodeBase64Url)
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
                commitEventId: frame.type === "group-invitation" ? frame.commitEventId : null,
                commitFingerprint:
                    frame.type === "group-invitation"
                        ? encodeBase64Url(frame.commitFingerprint)
                        : null,
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
        "consumedReferences",
        "groupId",
        "descriptor",
        "descriptorNonce",
        "descriptorBinding",
        "topicSecret",
        "keyPackageReference",
        "welcome",
        "tree",
        "commitSequence",
        "commitEventId",
        "commitFingerprint",
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
    const decoded: Uint8Array[] = [];
    let completed = false;
    const ownedBytes = (value: unknown, maximum: number, exact?: number): Uint8Array => {
        const result = bytes(value, maximum, exact);
        decoded.push(result);
        return result;
    };
    const complete = <Frame extends FriendControlFrame>(frame: Frame): Frame => {
        completed = true;
        return frame;
    };
    try {
        const value = object(JSON.parse(utf8Decode(encoded)) as unknown);
        if (value.version !== 1 || typeof value.type !== "string") {
            throw new Error("Invalid friend-control frame");
        }
        if (value.type === "profile-update" && allNull(value, ["profile"])) {
            const profileBytes = ownedBytes(value.profile, MAXIMUM_DESCRIPTOR_BYTES);
            try {
                return complete({
                    type: "profile-update",
                    profile: decodeProfilePayload(profileBytes),
                });
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
            const requestIdBytes = ownedBytes(value.requestId, 24, 24);
            zeroBytes(requestIdBytes);
            return complete({ type: "friendship-ended", requestId: value.requestId });
        }
        if (value.type === "key-package-announce" && allNull(value, ["reference", "keyPackage"])) {
            return complete({
                type: "key-package-announce",
                reference: ownedBytes(value.reference, 32, 32),
                keyPackage: ownedBytes(value.keyPackage, MAXIMUM_MLS_MATERIAL_BYTES),
            });
        }
        if (
            (value.type === "key-package-request" ||
                value.type === "key-package-consumed-ack" ||
                value.type === "key-package-retire") &&
            allNull(value, ["consumedReferences"]) &&
            Array.isArray(value.consumedReferences) &&
            value.consumedReferences.length <= 64
        ) {
            const consumedReferences = value.consumedReferences.map((reference) =>
                ownedBytes(reference, 32, 32),
            );
            if (
                new Set(consumedReferences.map(encodeBase64Url)).size !== consumedReferences.length
            ) {
                throw new Error("Duplicate consumed KeyPackage reference");
            }
            return complete({
                type: value.type,
                consumedReferences,
            });
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
                "commitEventId",
                "commitFingerprint",
            ]) &&
            typeof value.commitSequence === "string" &&
            /^[1-9]\d*$/.test(value.commitSequence) &&
            typeof value.commitEventId === "string"
        ) {
            const commitSequence = BigInt(value.commitSequence);
            if (commitSequence > 0xffff_ffff_ffff_ffffn) {
                throw new Error("Invalid invitation Commit sequence");
            }
            const commitEventIdBytes = ownedBytes(value.commitEventId, 32, 32);
            const commitEventId = encodeBase64Url(commitEventIdBytes);
            zeroBytes(commitEventIdBytes);
            return complete({
                type: "group-invitation",
                groupId: ownedBytes(value.groupId, 32, 32),
                descriptor: ownedBytes(value.descriptor, MAXIMUM_DESCRIPTOR_BYTES),
                descriptorNonce: ownedBytes(value.descriptorNonce, 32, 32),
                descriptorBinding: ownedBytes(value.descriptorBinding, 32, 32),
                topicSecret: ownedBytes(value.topicSecret, 32, 32),
                keyPackageReference: ownedBytes(value.keyPackageReference, 32, 32),
                welcome: ownedBytes(value.welcome, MAXIMUM_MLS_MATERIAL_BYTES),
                tree: ownedBytes(value.tree, MAXIMUM_MLS_MATERIAL_BYTES),
                commitSequence,
                commitEventId,
                commitFingerprint: ownedBytes(value.commitFingerprint, 32, 32),
            });
        }
        throw new Error("Unsupported friend-control frame");
    } finally {
        if (!completed) {
            for (const value of decoded) {
                zeroBytes(value);
            }
        }
    }
}
