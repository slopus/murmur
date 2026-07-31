import {
    decodeBase64Url,
    decodePrivateMessage,
    decodeSignedRelayEventWire,
    destroyIdentity,
    encodeBase64Url,
    encodePrivateMessage,
    encodeSignedRelayEventWire,
    importIdentityKeyPair,
    utf8Decode,
    utf8Encode,
    validateIdentityProfile,
    zeroBytes,
    type EncryptedProfile,
    type IdentityProfile,
    type SignedRelayEvent,
} from "@slopus/murmur";
import type { CliAccount, CliStoredMessage } from "../types.js";

/** Durable application outbox entry tied to one exact core relay event. */
export interface CliOutboundMessage {
    readonly event: SignedRelayEvent;
    readonly messageKey: string;
    readonly blobIds: readonly string[];
}

/** Strict outer boundary for one fully sealed profile payload. */
export interface CliProfileEnvelope {
    readonly encrypted: EncryptedProfile;
}

function record(value: unknown, fields: readonly string[], name: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error(`Invalid ${name}`);
    }
    const keys = Object.keys(value);
    if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
        throw new Error(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function encodeProfile(profile: IdentityProfile): {
    readonly name: string;
    readonly avatar?: string;
    readonly metadata?: Readonly<Record<string, string>>;
} {
    return {
        name: profile.name,
        ...(profile.avatar === undefined ? {} : { avatar: encodeBase64Url(profile.avatar) }),
        ...(profile.metadata === undefined ? {} : { metadata: { ...profile.metadata } }),
    };
}

function decodeProfile(value: unknown): IdentityProfile {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new Error("Invalid CLI account profile");
    }
    const profile = value as Record<string, unknown>;
    if (
        typeof profile.name !== "string" ||
        Object.keys(profile).some((key) => !["name", "avatar", "metadata"].includes(key)) ||
        (profile.avatar !== undefined && typeof profile.avatar !== "string") ||
        (profile.metadata !== undefined &&
            (typeof profile.metadata !== "object" ||
                profile.metadata === null ||
                Array.isArray(profile.metadata) ||
                Object.values(profile.metadata).some((item) => typeof item !== "string")))
    ) {
        throw new Error("Invalid CLI account profile");
    }
    return {
        name: profile.name,
        ...(profile.avatar === undefined
            ? {}
            : { avatar: decodeBase64Url(profile.avatar as string) }),
        ...(profile.metadata === undefined
            ? {}
            : { metadata: { ...(profile.metadata as Record<string, string>) } }),
    };
}

/** Encode one CLI account, including its secret identity seeds. */
export function encodeCliAccount(account: CliAccount): Uint8Array {
    validateIdentityProfile(account.profile);
    return utf8Encode(
        JSON.stringify({
            version: 1,
            signingSecretKey: encodeBase64Url(account.identity.signingSecretKey),
            encryptionSecretKey: encodeBase64Url(account.identity.encryptionSecretKey),
            profile: encodeProfile(account.profile),
        }),
    );
}

/** Decode and cryptographically reconstruct one CLI account. */
export function decodeCliAccount(bytes: Uint8Array): CliAccount {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "signingSecretKey", "encryptionSecretKey", "profile"],
        "CLI account",
    );
    if (
        value.version !== 1 ||
        typeof value.signingSecretKey !== "string" ||
        typeof value.encryptionSecretKey !== "string"
    ) {
        throw new Error("Invalid CLI account");
    }
    const profile = decodeProfile(value.profile);
    let signingSecretKey: Uint8Array | undefined;
    let encryptionSecretKey: Uint8Array | undefined;
    try {
        validateIdentityProfile(profile);
        signingSecretKey = decodeBase64Url(value.signingSecretKey);
        encryptionSecretKey = decodeBase64Url(value.encryptionSecretKey);
        const identity = importIdentityKeyPair(signingSecretKey, encryptionSecretKey);
        try {
            return { identity, profile };
        } catch (error: unknown) {
            destroyIdentity(identity);
            throw error;
        }
    } catch (error: unknown) {
        if (profile.avatar !== undefined) {
            zeroBytes(profile.avatar);
        }
        throw error;
    } finally {
        if (signingSecretKey !== undefined) {
            zeroBytes(signingSecretKey);
        }
        if (encryptionSecretKey !== undefined) {
            zeroBytes(encryptionSecretKey);
        }
    }
}

/** Encode one local history record. */
export function encodeCliStoredMessage(stored: CliStoredMessage): Uint8Array {
    const message = encodePrivateMessage(stored.message);
    try {
        return utf8Encode(
            JSON.stringify({
                version: 1,
                sequence: stored.sequence,
                direction: stored.direction,
                conversationId: stored.conversationId,
                status: stored.status,
                message: encodeBase64Url(message),
            }),
        );
    } finally {
        zeroBytes(message);
    }
}

/** Decode one validated local history record. */
export function decodeCliStoredMessage(bytes: Uint8Array): CliStoredMessage {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "sequence", "direction", "conversationId", "status", "message"],
        "CLI message",
    );
    if (
        value.version !== 1 ||
        typeof value.sequence !== "number" ||
        !Number.isSafeInteger(value.sequence) ||
        value.sequence < 1 ||
        (value.direction !== "incoming" && value.direction !== "outgoing") ||
        typeof value.conversationId !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(value.conversationId) ||
        encodeBase64Url(decodeBase64Url(value.conversationId)) !== value.conversationId ||
        !["received", "pending", "sent"].includes(value.status as string) ||
        typeof value.message !== "string"
    ) {
        throw new Error("Invalid CLI message");
    }
    const message = decodeBase64Url(value.message);
    try {
        return {
            sequence: value.sequence,
            direction: value.direction,
            conversationId: value.conversationId,
            status: value.status as CliStoredMessage["status"],
            message: decodePrivateMessage(message),
        };
    } finally {
        zeroBytes(message);
    }
}

/** Encode one exact event-to-message/blob application outbox mapping. */
export function encodeCliOutboundMessage(outbound: CliOutboundMessage): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            version: 1,
            event: encodeBase64Url(encodeSignedRelayEventWire(outbound.event)),
            messageKey: outbound.messageKey,
            blobIds: outbound.blobIds,
        }),
    );
}

/** Decode one validated event-to-message/blob application outbox mapping. */
export function decodeCliOutboundMessage(bytes: Uint8Array): CliOutboundMessage {
    const value = record(
        JSON.parse(utf8Decode(bytes)) as unknown,
        ["version", "event", "messageKey", "blobIds"],
        "CLI outbound message",
    );
    if (
        value.version !== 1 ||
        typeof value.event !== "string" ||
        typeof value.messageKey !== "string" ||
        value.messageKey.length === 0 ||
        value.messageKey.length > 4_096 ||
        !Array.isArray(value.blobIds) ||
        value.blobIds.length > 64 ||
        value.blobIds.some(
            (blobId) => typeof blobId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(blobId),
        )
    ) {
        throw new Error("Invalid CLI outbound message");
    }
    return {
        event: decodeSignedRelayEventWire(decodeBase64Url(value.event)),
        messageKey: value.messageKey,
        blobIds: value.blobIds as string[],
    };
}

/** Encode one fully sealed profile and private KeyPackage payload. */
export function encodeCliProfileEnvelope(encrypted: EncryptedProfile): Uint8Array {
    return utf8Encode(
        JSON.stringify({
            kind: "murmur.profile.v2",
            encrypted,
        }),
    );
}

/** Decode the strict profile relay payload boundary. */
export function decodeCliProfileEnvelope(bytes: Uint8Array): CliProfileEnvelope {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new Error("Invalid CLI profile envelope");
    }
    const candidate = parsed as Record<string, unknown>;
    const envelope = record(candidate, ["kind", "encrypted"], "CLI profile envelope");
    if (candidate.kind !== "murmur.profile.v2") {
        throw new Error("Invalid CLI profile envelope");
    }
    const encrypted = record(
        envelope.encrypted,
        ["version", "recipient", "ephemeralPublicKey", "nonce", "ciphertext"],
        "CLI encrypted profile",
    );
    if (
        encrypted.version !== 1 ||
        typeof encrypted.recipient !== "string" ||
        typeof encrypted.ephemeralPublicKey !== "string" ||
        typeof encrypted.nonce !== "string" ||
        typeof encrypted.ciphertext !== "string"
    ) {
        throw new Error("Invalid CLI encrypted profile");
    }
    return {
        encrypted: {
            version: 1,
            recipient: encrypted.recipient,
            ephemeralPublicKey: encrypted.ephemeralPublicKey,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        },
    };
}
