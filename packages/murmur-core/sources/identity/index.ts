import type { IdentityKeyPair, IdentityPublicKeys } from "../crypto/index.js";
import { hashBytes, openBox, sealBox, signBytes, verifyBytes } from "../crypto/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    utf8Decode,
    utf8Encode,
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
} from "./types.js";
export { ContactBook } from "./contactBook.js";

const MAX_PROFILE_BYTES = 1024 * 1024;
const MAX_PROFILE_PLAINTEXT_BYTES = Math.ceil((MAX_PROFILE_BYTES * 4) / 3) + 1_024;
const MAX_ENCRYPTED_PROFILE_BYTES = MAX_PROFILE_PLAINTEXT_BYTES + 16;
const MAX_ENCRYPTED_PROFILE_BASE64URL_CHARACTERS = Math.ceil((MAX_ENCRYPTED_PROFILE_BYTES * 4) / 3);

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

/** Reserved topic on which an identity receives contact and topic invitations. */
export function identityInboxTopic(identity: Pick<IdentityPublicKeys, "signingKey">): string {
    return `identity:${encodeBase64Url(hashBytes(identity.signingKey))}`;
}

function profileSignaturePayload(profileBytes: Uint8Array, recipient: string): Uint8Array {
    return canonicalJsonBytes({
        profile: encodeBase64Url(profileBytes),
        recipient,
        version: 1,
    });
}

function profileAssociatedData(sender: SerializedPublicIdentity, recipient: string): Uint8Array {
    return canonicalJsonBytes({
        recipient,
        sender: {
            encryptionKey: sender.encryptionKey,
            signingKey: sender.signingKey,
        },
        version: 1,
    });
}

/**
 * Sign a profile and encrypt it directly to a contact.
 *
 * The serialized profile is limited to one MiB before encryption.
 */
export function encryptProfileForContact(
    sender: IdentityKeyPair,
    recipient: IdentityPublicKeys,
    profile: IdentityProfile,
): EncryptedProfile {
    const profileBytes = encodeProfilePayload(profile);
    if (profileBytes.length > MAX_PROFILE_BYTES) {
        throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
    }

    const recipientId = identityId(recipient);
    const signature = signBytes(sender, profileSignaturePayload(profileBytes, recipientId));
    const plaintext = utf8Encode(
        JSON.stringify({
            profile: encodeBase64Url(profileBytes),
            signature: encodeBase64Url(signature),
        }),
    );
    const serializedSender = serializePublicIdentity(sender);
    const box = sealBox(recipient, plaintext, profileAssociatedData(serializedSender, recipientId));

    return {
        version: 1,
        sender: serializedSender,
        recipient: recipientId,
        ephemeralPublicKey: encodeBase64Url(box.ephemeralPublicKey),
        nonce: encodeBase64Url(box.nonce),
        ciphertext: encodeBase64Url(box.ciphertext),
    };
}

/** Decrypt a profile and verify its owner's signature. */
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

    const sender = deserializePublicIdentity(encrypted.sender);
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
        profileAssociatedData(encrypted.sender, encrypted.recipient),
    );
    if (plaintext.length > MAX_PROFILE_PLAINTEXT_BYTES) {
        throw new Error("Encrypted profile plaintext is too large");
    }
    const decoded: unknown = JSON.parse(utf8Decode(plaintext));
    if (
        typeof decoded !== "object" ||
        decoded === null ||
        !("profile" in decoded) ||
        !("signature" in decoded) ||
        typeof decoded.profile !== "string" ||
        typeof decoded.signature !== "string"
    ) {
        throw new Error("Invalid encrypted profile payload");
    }

    const profileBytes = decodeBase64Url(decoded.profile);
    if (profileBytes.length > MAX_PROFILE_BYTES) {
        throw new Error(`Profile exceeds ${MAX_PROFILE_BYTES} bytes`);
    }
    const signature = decodeBase64Url(decoded.signature);
    if (
        !verifyBytes(sender, profileSignaturePayload(profileBytes, encrypted.recipient), signature)
    ) {
        throw new Error("Invalid profile signature");
    }

    return {
        identity: sender,
        profile: decodeProfilePayload(profileBytes),
    };
}
