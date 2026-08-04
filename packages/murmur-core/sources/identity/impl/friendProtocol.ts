import type { IdentityKeyPair, IdentityPublicKey } from "../../crypto/index.js";
import { hashBytes, openBox, sealBox, signBytes, verifyBytes } from "../../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../../utils/index.js";
import type {
    FriendRequestEnvelope,
    FriendRequestInput,
    FriendResponseEnvelope,
    FriendResponseInput,
    IdentityProfile,
    OpenedFriendRequest,
    OpenedFriendResponse,
} from "../types.js";
import { deserializePublicIdentity, identityId, serializePublicIdentity } from "./identityCodec.js";
import { decodeProfilePayload, encodeProfilePayload } from "./profileCodec.js";

const MAX_PROFILE_BYTES = 1024 * 1024;
const MAX_PRIVATE_DATA_BYTES = 256 * 1024;
const MAX_RESPONSE_ADDRESS_BYTES = 4096;
const MAX_CIPHERTEXT_BYTES = 2 * 1024 * 1024;

type FriendEnvelope = FriendRequestEnvelope | FriendResponseEnvelope;

function validateId(id: string): void {
    const decoded = decodeBase64Url(id);
    if (decoded.length !== 24 || encodeBase64Url(decoded) !== id) {
        throw new Error("Friend exchange ID must encode exactly 24 bytes");
    }
}

function validateResponseAddress(address: string): void {
    const length = utf8Encode(address).length;
    if (length === 0 || length > MAX_RESPONSE_ADDRESS_BYTES) {
        throw new Error(`Response address must contain 1 to ${MAX_RESPONSE_ADDRESS_BYTES} bytes`);
    }
}

function validateTimeFreePrivateData(value: Uint8Array | undefined): Uint8Array {
    const data = value ?? new Uint8Array();
    if (!(data instanceof Uint8Array) || data.length > MAX_PRIVATE_DATA_BYTES) {
        throw new Error(`Friend private data exceeds ${MAX_PRIVATE_DATA_BYTES} bytes`);
    }
    return data;
}

function associatedData(
    type: FriendEnvelope["type"],
    recipient: string,
    sender: string | null,
): Uint8Array {
    return canonicalJsonBytes({ recipient, sender, type, version: 1 });
}

function signaturePayload(
    type: FriendEnvelope["type"],
    recipient: string,
    content: Readonly<Record<string, string | number | boolean | null>>,
): Uint8Array {
    return canonicalJsonBytes({ ...content, recipient, type, version: 1 });
}

function encodeProfile(profile: IdentityProfile): string {
    const bytes = encodeProfilePayload(profile);
    try {
        if (bytes.length > MAX_PROFILE_BYTES) {
            throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
        }
        return encodeBase64Url(bytes);
    } finally {
        zeroBytes(bytes);
    }
}

function decodeProfile(encoded: string): IdentityProfile {
    const bytes = decodeBase64Url(encoded);
    try {
        if (bytes.length > MAX_PROFILE_BYTES) {
            throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
        }
        return decodeProfilePayload(bytes);
    } finally {
        zeroBytes(bytes);
    }
}

function sealSigned(
    type: FriendEnvelope["type"],
    signer: IdentityKeyPair,
    recipient: IdentityPublicKey,
    content: Readonly<Record<string, string | boolean | null>>,
): FriendEnvelope {
    const recipientId = identityId(recipient);
    const signed = signaturePayload(type, recipientId, content);
    let signature: Uint8Array | undefined;
    let plaintext: Uint8Array | undefined;
    let aad: Uint8Array | undefined;
    try {
        signature = signBytes(signer, signed);
        plaintext = utf8Encode(
            JSON.stringify({
                ...content,
                signature: encodeBase64Url(signature),
            }),
        );
        aad = associatedData(
            type,
            recipientId,
            type === "friend-response" ? identityId(signer) : null,
        );
        const box = sealBox(recipient, plaintext, aad);
        return {
            version: 1,
            type,
            ephemeralPublicKey: encodeBase64Url(box.ephemeralPublicKey),
            nonce: encodeBase64Url(box.nonce),
            ciphertext: encodeBase64Url(box.ciphertext),
        };
    } finally {
        zeroBytes(signed);
        if (signature !== undefined) {
            zeroBytes(signature);
        }
        if (plaintext !== undefined) {
            zeroBytes(plaintext);
        }
        if (aad !== undefined) {
            zeroBytes(aad);
        }
    }
}

function openSigned(
    recipient: IdentityKeyPair,
    envelope: FriendEnvelope,
    expectedSender?: IdentityPublicKey,
): Record<string, unknown> {
    const fields = ["version", "type", "ephemeralPublicKey", "nonce", "ciphertext"];
    const recipientId = identityId(recipient);
    if (
        typeof envelope !== "object" ||
        envelope === null ||
        Array.isArray(envelope) ||
        Object.keys(envelope).length !== fields.length ||
        Object.keys(envelope).some((key) => !fields.includes(key)) ||
        envelope.version !== 1 ||
        envelope.ciphertext.length > Math.ceil((MAX_CIPHERTEXT_BYTES * 4) / 3) ||
        decodeBase64Url(envelope.ephemeralPublicKey).length !== 32 ||
        decodeBase64Url(envelope.nonce).length !== 12
    ) {
        throw new Error("Invalid or misaddressed friend envelope");
    }
    if (envelope.type === "friend-response" && expectedSender === undefined) {
        throw new Error("Friend response requires an expected sender");
    }
    const ciphertext = decodeBase64Url(envelope.ciphertext);
    if (ciphertext.length > MAX_CIPHERTEXT_BYTES) {
        throw new Error("Friend envelope ciphertext is too large");
    }
    const aad = associatedData(
        envelope.type,
        recipientId,
        envelope.type === "friend-response" && expectedSender !== undefined
            ? identityId(expectedSender)
            : null,
    );
    let plaintext: Uint8Array | undefined;
    try {
        plaintext = openBox(
            recipient,
            {
                ephemeralPublicKey: decodeBase64Url(envelope.ephemeralPublicKey),
                nonce: decodeBase64Url(envelope.nonce),
                ciphertext,
            },
            aad,
        );
        const decoded: unknown = JSON.parse(utf8Decode(plaintext));
        if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
            throw new Error("Invalid friend envelope payload");
        }
        return decoded as Record<string, unknown>;
    } finally {
        zeroBytes(ciphertext);
        zeroBytes(aad);
        if (plaintext !== undefined) {
            zeroBytes(plaintext);
        }
    }
}

/** Create a signed, recipient-confidential friend request. */
export function createFriendRequest(
    sender: IdentityKeyPair,
    recipient: IdentityPublicKey,
    input: FriendRequestInput,
): FriendRequestEnvelope {
    validateId(input.id);
    validateResponseAddress(input.responseAddress);
    const privateData = validateTimeFreePrivateData(input.privateData);
    return sealSigned("friend-request", sender, recipient, {
        id: input.id,
        sender: serializePublicIdentity(sender).publicKey,
        recipient: identityId(recipient),
        responseAddress: input.responseAddress,
        profile: encodeProfile(input.profile),
        privateData: encodeBase64Url(privateData),
    }) as FriendRequestEnvelope;
}

/** Open and authenticate a friend request addressed to this identity. */
export function openFriendRequest(
    recipient: IdentityKeyPair,
    envelope: FriendRequestEnvelope,
): OpenedFriendRequest {
    if (envelope.type !== "friend-request") {
        throw new Error("Expected a friend request");
    }
    const payload = openSigned(recipient, envelope);
    const expected = [
        "id",
        "sender",
        "recipient",
        "responseAddress",
        "profile",
        "privateData",
        "signature",
    ];
    if (
        Object.keys(payload).length !== expected.length ||
        Object.keys(payload).some((key) => !expected.includes(key)) ||
        typeof payload.id !== "string" ||
        typeof payload.sender !== "string" ||
        typeof payload.recipient !== "string" ||
        payload.recipient !== identityId(recipient) ||
        typeof payload.responseAddress !== "string" ||
        typeof payload.profile !== "string" ||
        typeof payload.privateData !== "string" ||
        typeof payload.signature !== "string"
    ) {
        throw new Error("Invalid friend request payload");
    }
    validateId(payload.id);
    validateResponseAddress(payload.responseAddress);
    const sender = deserializePublicIdentity({ publicKey: payload.sender });
    const privateData = decodeBase64Url(payload.privateData);
    const signature = decodeBase64Url(payload.signature);
    const signed = signaturePayload("friend-request", identityId(recipient), {
        id: payload.id,
        sender: payload.sender,
        recipient: payload.recipient,
        responseAddress: payload.responseAddress,
        profile: payload.profile,
        privateData: payload.privateData,
    });
    try {
        validateTimeFreePrivateData(privateData);
        if (!verifyBytes(sender, signed, signature)) {
            throw new Error("Invalid friend request signature");
        }
        return {
            id: payload.id,
            sender,
            responseAddress: payload.responseAddress,
            profile: decodeProfile(payload.profile),
            ...(privateData.length === 0 ? {} : { privateData: privateData.slice() }),
        };
    } finally {
        zeroBytes(privateData);
        zeroBytes(signature);
        zeroBytes(signed);
    }
}

/** Create an authenticated encrypted response to one friend request. */
export function createFriendResponse(
    responder: IdentityKeyPair,
    requester: IdentityPublicKey,
    input: FriendResponseInput,
): FriendResponseEnvelope {
    validateId(input.id);
    validateId(input.requestId);
    if (input.decision === "accepted") {
        validateResponseAddress(input.responseAddress);
    }
    const privateData = validateTimeFreePrivateData(
        input.decision === "accepted" ? input.privateData : undefined,
    );
    return sealSigned("friend-response", responder, requester, {
        id: input.id,
        requestId: input.requestId,
        responder: serializePublicIdentity(responder).publicKey,
        recipient: identityId(requester),
        decision: input.decision,
        responseAddress: input.decision === "accepted" ? input.responseAddress : null,
        profile: input.decision === "accepted" ? encodeProfile(input.profile) : null,
        privateData: input.decision === "accepted" ? encodeBase64Url(privateData) : null,
    }) as FriendResponseEnvelope;
}

/** Open and authenticate a friend response addressed to this identity. */
export function openFriendResponse(
    recipient: IdentityKeyPair,
    expectedResponder: IdentityPublicKey,
    envelope: FriendResponseEnvelope,
): OpenedFriendResponse {
    if (envelope.type !== "friend-response") {
        throw new Error("Expected a friend response");
    }
    const payload = openSigned(recipient, envelope, expectedResponder);
    const expected = [
        "id",
        "requestId",
        "responder",
        "recipient",
        "decision",
        "responseAddress",
        "profile",
        "privateData",
        "signature",
    ];
    if (
        Object.keys(payload).length !== expected.length ||
        Object.keys(payload).some((key) => !expected.includes(key)) ||
        typeof payload.id !== "string" ||
        typeof payload.requestId !== "string" ||
        typeof payload.responder !== "string" ||
        typeof payload.recipient !== "string" ||
        payload.recipient !== identityId(recipient) ||
        (payload.decision !== "accepted" && payload.decision !== "rejected") ||
        (payload.responseAddress !== null && typeof payload.responseAddress !== "string") ||
        (payload.profile !== null && typeof payload.profile !== "string") ||
        (payload.privateData !== null && typeof payload.privateData !== "string") ||
        typeof payload.signature !== "string"
    ) {
        throw new Error("Invalid friend response payload");
    }
    validateId(payload.id);
    validateId(payload.requestId);
    const responder = deserializePublicIdentity({ publicKey: payload.responder });
    if (!equalBytes(responder.publicKey, expectedResponder.publicKey)) {
        throw new Error("Friend response is from an unexpected identity");
    }
    const signed = signaturePayload("friend-response", identityId(recipient), {
        id: payload.id,
        requestId: payload.requestId,
        responder: payload.responder,
        recipient: payload.recipient,
        decision: payload.decision,
        responseAddress: payload.responseAddress,
        profile: payload.profile,
        privateData: payload.privateData,
    });
    const signature = decodeBase64Url(payload.signature);
    try {
        if (!verifyBytes(responder, signed, signature)) {
            throw new Error("Invalid friend response signature");
        }
        if (payload.decision === "rejected") {
            if (
                payload.responseAddress !== null ||
                payload.profile !== null ||
                payload.privateData !== null
            ) {
                throw new Error("Rejected friend response carries unexpected data");
            }
            return {
                id: payload.id,
                requestId: payload.requestId,
                responder,
                decision: "rejected",
            };
        }
        if (
            typeof payload.responseAddress !== "string" ||
            typeof payload.profile !== "string" ||
            typeof payload.privateData !== "string"
        ) {
            throw new Error("Accepted friend response is incomplete");
        }
        validateResponseAddress(payload.responseAddress);
        const privateData = decodeBase64Url(payload.privateData);
        try {
            validateTimeFreePrivateData(privateData);
            return {
                id: payload.id,
                requestId: payload.requestId,
                responder,
                decision: "accepted",
                responseAddress: payload.responseAddress,
                profile: decodeProfile(payload.profile),
                ...(privateData.length === 0 ? {} : { privateData: privateData.slice() }),
            };
        } finally {
            zeroBytes(privateData);
        }
    } finally {
        zeroBytes(signed);
        zeroBytes(signature);
    }
}

/** Hash authenticated request content for durable replay/collision decisions. */
export function friendRequestFingerprint(opened: OpenedFriendRequest): Uint8Array {
    const preimage = canonicalJsonBytes({
        id: opened.id,
        sender: identityId(opened.sender),
        responseAddress: opened.responseAddress,
        profile: encodeProfile(opened.profile),
        privateData: encodeBase64Url(opened.privateData ?? new Uint8Array()),
        type: "friend-request",
        version: 1,
    });
    try {
        return hashBytes(preimage);
    } finally {
        zeroBytes(preimage);
    }
}

/** Hash authenticated response content for durable replay/collision decisions. */
export function friendResponseFingerprint(opened: OpenedFriendResponse): Uint8Array {
    const preimage = canonicalJsonBytes({
        id: opened.id,
        requestId: opened.requestId,
        responder: identityId(opened.responder),
        decision: opened.decision,
        responseAddress: opened.decision === "accepted" ? opened.responseAddress : null,
        profile: opened.decision === "accepted" ? encodeProfile(opened.profile) : null,
        privateData:
            opened.decision === "accepted"
                ? encodeBase64Url(opened.privateData ?? new Uint8Array())
                : null,
        type: "friend-response",
        version: 1,
    });
    try {
        return hashBytes(preimage);
    } finally {
        zeroBytes(preimage);
    }
}
