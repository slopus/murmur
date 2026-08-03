import { x25519 } from "@noble/curves/ed25519";
import type { IdentityKeyPair, IdentityPublicKeys } from "../crypto/index.js";
import { hashBytes, openBox, sealBox, signBytes, verifyBytes } from "../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import { decodeProfilePayload, encodeProfilePayload } from "./impl/profileCodec.js";
import type {
    EncryptedProfile,
    IdentityProfile,
    OpenedProfile,
    SerializedPublicIdentity,
} from "./types.js";

export type {
    Contact,
    EncryptedProfile,
    IdentityProfile,
    OpenedProfile,
    SerializedPublicIdentity,
    FriendQuery,
    FriendRecord,
    FriendStatus,
} from "./types.js";
export { ContactBook } from "./contactBook.js";
export { FriendBook } from "./friendBook.js";

const MAX_PROFILE_BYTES = 1024 * 1024;
const MAX_PROFILE_PRIVATE_DATA_BYTES = 256 * 1024;
const MAX_PROFILE_PLAINTEXT_BYTES =
    Math.ceil(((MAX_PROFILE_BYTES + MAX_PROFILE_PRIVATE_DATA_BYTES) * 4) / 3) + 2_048;
const MAX_ENCRYPTED_PROFILE_BYTES = MAX_PROFILE_PLAINTEXT_BYTES + 16;
const MAX_ENCRYPTED_PROFILE_BASE64URL_CHARACTERS = Math.ceil((MAX_ENCRYPTED_PROFILE_BYTES * 4) / 3);

/** Validate one profile against every core serialization and size bound. */
export function validateIdentityProfile(profile: IdentityProfile): void {
    const bytes = encodeProfilePayload(profile);
    try {
        if (bytes.length > MAX_PROFILE_BYTES) {
            throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
        }
    } finally {
        zeroBytes(bytes);
    }
}

/** Serialize an identity's public keys for a wire boundary. */
export function serializePublicIdentity(identity: IdentityPublicKeys): SerializedPublicIdentity {
    if (identity.signingKey.length !== 32 || identity.encryptionKey.length !== 32) {
        throw new Error("Identity public keys must be 32 bytes");
    }
    return {
        signingKey: encodeBase64Url(identity.signingKey),
        encryptionKey: encodeBase64Url(identity.encryptionKey),
    };
}

/** Decode and validate public identity keys. */
export function deserializePublicIdentity(identity: SerializedPublicIdentity): IdentityPublicKeys {
    const signingKey = decodeBase64Url(identity.signingKey);
    const encryptionKey = decodeBase64Url(identity.encryptionKey);
    if (signingKey.length !== 32 || encryptionKey.length !== 32) {
        throw new Error("Identity public keys must be 32 bytes");
    }
    return { signingKey, encryptionKey };
}

/** Stable routing identifier for an identity. */
export function identityId(identity: Pick<IdentityPublicKeys, "signingKey">): string {
    return encodeBase64Url(identity.signingKey);
}

/**
 * Public first-contact inbox for one identity.
 *
 * Anyone with the public signing key can read this topic. Contact payloads seal
 * the sender identity and use one-use relay event authors, so observers learn
 * that N unlinkable contact requests exist, but not which identities sent
 * them. Ongoing traffic must use `pairwiseTopic` instead.
 */
export function identityInboxTopic(identity: Pick<IdentityPublicKeys, "signingKey">): string {
    return `identity:${encodeBase64Url(hashBytes(identity.signingKey))}`;
}

/**
 * Derive a symmetric capability topic from two identities' X25519 secret.
 *
 * The domain string and canonically ordered public encryption keys bind the
 * secret to this topic kind and identity pair. Possessing both public identity
 * tokens is insufficient to derive the result.
 */
export function pairwiseTopic(self: IdentityKeyPair, peer: IdentityPublicKeys): string {
    if (
        self.encryptionSecretKey.length !== 32 ||
        self.encryptionKey.length !== 32 ||
        peer.encryptionKey.length !== 32
    ) {
        throw new Error("Identity encryption keys must be 32 bytes");
    }
    const derivedPublicKey = x25519.getPublicKey(self.encryptionSecretKey);
    try {
        if (!equalBytes(derivedPublicKey, self.encryptionKey)) {
            throw new Error("Identity encryption public key does not match its secret key");
        }
    } finally {
        zeroBytes(derivedPublicKey);
    }
    const publicKeys = [
        encodeBase64Url(self.encryptionKey),
        encodeBase64Url(peer.encryptionKey),
    ].sort();
    const sharedSecret = x25519.getSharedSecret(self.encryptionSecretKey, peer.encryptionKey);
    let preimage: Uint8Array | undefined;
    let digest: Uint8Array | undefined;
    try {
        preimage = canonicalJsonBytes({
            context: "murmur/pairwise-topic/x25519-sha256/v1",
            publicKeys,
            sharedSecret: encodeBase64Url(sharedSecret),
        });
        digest = hashBytes(preimage);
        return `pairwise:${encodeBase64Url(digest)}`;
    } finally {
        zeroBytes(sharedSecret);
        if (preimage !== undefined) {
            zeroBytes(preimage);
        }
        if (digest !== undefined) {
            zeroBytes(digest);
        }
    }
}

function profileSignaturePayload(
    profileBytes: Uint8Array,
    privateData: Uint8Array,
    recipient: string,
): Uint8Array {
    return canonicalJsonBytes({
        privateData: encodeBase64Url(privateData),
        profile: encodeBase64Url(profileBytes),
        recipient,
        version: 1,
    });
}

function profileAssociatedData(recipient: string): Uint8Array {
    return canonicalJsonBytes({
        recipient,
        version: 1,
    });
}

/**
 * Sign a profile and optional private application bytes, then encrypt both and
 * the sender identity directly to a contact.
 *
 * The serialized profile is limited to one MiB before encryption.
 */
export function encryptProfileForContact(
    sender: IdentityKeyPair,
    recipient: IdentityPublicKeys,
    profile: IdentityProfile,
    privateData: Uint8Array = new Uint8Array(),
): EncryptedProfile {
    if (
        !(privateData instanceof Uint8Array) ||
        privateData.length > MAX_PROFILE_PRIVATE_DATA_BYTES
    ) {
        throw new Error(`Profile private data exceeds ${MAX_PROFILE_PRIVATE_DATA_BYTES} bytes`);
    }
    const profileBytes = encodeProfilePayload(profile);
    if (profileBytes.length > MAX_PROFILE_BYTES) {
        throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
    }

    let signature: Uint8Array | undefined;
    let signaturePayload: Uint8Array | undefined;
    let plaintext: Uint8Array | undefined;
    try {
        const recipientId = identityId(recipient);
        signaturePayload = profileSignaturePayload(profileBytes, privateData, recipientId);
        signature = signBytes(sender, signaturePayload);
        plaintext = utf8Encode(
            JSON.stringify({
                sender: serializePublicIdentity(sender),
                privateData: encodeBase64Url(privateData),
                profile: encodeBase64Url(profileBytes),
                signature: encodeBase64Url(signature),
            }),
        );
        const box = sealBox(recipient, plaintext, profileAssociatedData(recipientId));
        return {
            version: 1,
            recipient: recipientId,
            ephemeralPublicKey: encodeBase64Url(box.ephemeralPublicKey),
            nonce: encodeBase64Url(box.nonce),
            ciphertext: encodeBase64Url(box.ciphertext),
        };
    } finally {
        zeroBytes(profileBytes);
        if (signature !== undefined) {
            zeroBytes(signature);
        }
        if (signaturePayload !== undefined) {
            zeroBytes(signaturePayload);
        }
        if (plaintext !== undefined) {
            zeroBytes(plaintext);
        }
    }
}

/** Decrypt a profile/private-data bundle and verify its owner's signature. */
export function decryptContactProfile(
    recipient: IdentityKeyPair,
    encrypted: EncryptedProfile,
): OpenedProfile {
    if (encrypted.version !== 1 || encrypted.recipient !== identityId(recipient)) {
        throw new Error("Encrypted profile is not addressed to this identity");
    }
    if (encrypted.ciphertext.length > MAX_ENCRYPTED_PROFILE_BASE64URL_CHARACTERS) {
        throw new Error("Encrypted profile ciphertext is too large");
    }

    const ciphertext = decodeBase64Url(encrypted.ciphertext);
    if (ciphertext.length > MAX_ENCRYPTED_PROFILE_BYTES) {
        throw new Error("Encrypted profile ciphertext is too large");
    }
    const plaintext = openBox(
        recipient,
        {
            ephemeralPublicKey: decodeBase64Url(encrypted.ephemeralPublicKey),
            nonce: decodeBase64Url(encrypted.nonce),
            ciphertext,
        },
        profileAssociatedData(encrypted.recipient),
    );
    let profileBytes: Uint8Array | undefined;
    let privateData: Uint8Array | undefined;
    let signaturePayload: Uint8Array | undefined;
    try {
        if (plaintext.length > MAX_PROFILE_PLAINTEXT_BYTES) {
            throw new Error("Encrypted profile plaintext is too large");
        }
        const decoded: unknown = JSON.parse(utf8Decode(plaintext));
        if (
            typeof decoded !== "object" ||
            decoded === null ||
            Array.isArray(decoded) ||
            !("sender" in decoded) ||
            typeof decoded.sender !== "object" ||
            decoded.sender === null ||
            Array.isArray(decoded.sender) ||
            !("privateData" in decoded) ||
            typeof decoded.privateData !== "string" ||
            !("profile" in decoded) ||
            !("signature" in decoded) ||
            typeof decoded.profile !== "string" ||
            typeof decoded.signature !== "string" ||
            Object.keys(decoded).some(
                (key) => !["sender", "privateData", "profile", "signature"].includes(key),
            )
        ) {
            throw new Error("Invalid encrypted profile payload");
        }
        const serializedSender = decoded.sender as Record<string, unknown>;
        if (
            typeof serializedSender.signingKey !== "string" ||
            typeof serializedSender.encryptionKey !== "string" ||
            Object.keys(serializedSender).some(
                (key) => !["signingKey", "encryptionKey"].includes(key),
            )
        ) {
            throw new Error("Invalid encrypted profile sender");
        }
        const sender = deserializePublicIdentity({
            signingKey: serializedSender.signingKey,
            encryptionKey: serializedSender.encryptionKey,
        });
        profileBytes = decodeBase64Url(decoded.profile);
        privateData = decodeBase64Url(decoded.privateData);
        if (profileBytes.length > MAX_PROFILE_BYTES) {
            throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
        }
        if (privateData.length > MAX_PROFILE_PRIVATE_DATA_BYTES) {
            throw new Error(`Profile private data exceeds ${MAX_PROFILE_PRIVATE_DATA_BYTES} bytes`);
        }
        const signature = decodeBase64Url(decoded.signature);
        signaturePayload = profileSignaturePayload(profileBytes, privateData, encrypted.recipient);
        if (!verifyBytes(sender, signaturePayload, signature)) {
            throw new Error("Invalid profile signature");
        }
        return {
            identity: sender,
            profile: decodeProfilePayload(profileBytes),
            ...(privateData.length === 0 ? {} : { privateData: privateData.slice() }),
        };
    } finally {
        zeroBytes(plaintext);
        if (profileBytes !== undefined) {
            zeroBytes(profileBytes);
        }
        if (privateData !== undefined) {
            zeroBytes(privateData);
        }
        if (signaturePayload !== undefined) {
            zeroBytes(signaturePayload);
        }
    }
}
