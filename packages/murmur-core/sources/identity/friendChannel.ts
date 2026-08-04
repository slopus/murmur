import { gcm } from "@noble/ciphers/aes";
import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import type { IdentityKeyPair, IdentityPublicKey } from "../crypto/index.js";
import {
    deriveSharedSecret,
    hashBytes,
    randomBytes,
    signBytes,
    verifyBytes,
} from "../crypto/index.js";
import type { MurmurStore } from "../storage/index.js";
import {
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    utf8Decode,
    utf8Encode,
    zeroBytes,
} from "../utils/index.js";
import { identityId } from "./impl/identityCodec.js";
import type {
    AcceptedFriendControl,
    FriendChannelOptions,
    FriendControlEnvelope,
    FriendControlMessage,
    FriendControlRetention,
    OpenedFriendControl,
    PersistFriendControl,
} from "./types.js";

const CONTROL_KEY_BYTES = 32;
const CONTROL_NONCE_BYTES = 12;
const MAX_CONTROL_PAYLOAD_BYTES = 1024 * 1024;
const MAX_CONTROL_CIPHERTEXT_BYTES = Math.ceil((MAX_CONTROL_PAYLOAD_BYTES * 4) / 3) + 2048;
const ID_CHARACTERS = 32;
const PUBLIC_KEY_CHARACTERS = 43;
const NONCE_CHARACTERS = 16;
const SIGNATURE_CHARACTERS = 86;
const MAX_CONTROL_PAYLOAD_CHARACTERS = Math.ceil((MAX_CONTROL_PAYLOAD_BYTES * 4) / 3);
const MAX_CONTROL_CIPHERTEXT_CHARACTERS = Math.ceil((MAX_CONTROL_CIPHERTEXT_BYTES * 4) / 3);
const DERIVATION_INFO = utf8Encode("murmur/friend-channel/v1");

function validateControlMessage(message: FriendControlMessage): void {
    if (message.id.length !== ID_CHARACTERS) {
        throw new Error("Invalid friend-control message");
    }
    const id = decodeBase64Url(message.id);
    if (
        id.length !== 24 ||
        encodeBase64Url(id) !== message.id ||
        !Number.isSafeInteger(message.sentAt) ||
        message.sentAt < 0 ||
        !(message.payload instanceof Uint8Array) ||
        message.payload.length > MAX_CONTROL_PAYLOAD_BYTES
    ) {
        throw new Error("Invalid friend-control message");
    }
    if (
        message.retention.kind !== "durable" &&
        (message.retention.kind !== "temporary" ||
            !Number.isSafeInteger(message.retention.expiresAt) ||
            message.retention.expiresAt < message.sentAt)
    ) {
        throw new Error("Invalid friend-control retention");
    }
}

function retentionJson(retention: FriendControlRetention):
    | { readonly kind: "durable"; readonly expiresAt: null }
    | {
          readonly kind: "temporary";
          readonly expiresAt: number;
      } {
    return retention.kind === "durable"
        ? { kind: "durable", expiresAt: null }
        : { kind: "temporary", expiresAt: retention.expiresAt };
}

function channelSalt(self: IdentityPublicKey, peer: IdentityPublicKey): Uint8Array {
    const identities = [identityId(self), identityId(peer)].sort();
    return hashBytes(canonicalJsonBytes({ context: "murmur/friend-channel/salt/v1", identities }));
}

function envelopeAssociatedData(
    sender: IdentityPublicKey,
    recipient: IdentityPublicKey,
): Uint8Array {
    return canonicalJsonBytes({
        recipient: identityId(recipient),
        sender: identityId(sender),
        type: "friend-control",
        version: 1,
    });
}

function messageSignaturePayload(
    sender: IdentityPublicKey,
    recipient: IdentityPublicKey,
    message: FriendControlMessage,
): Uint8Array {
    return canonicalJsonBytes({
        id: message.id,
        payload: encodeBase64Url(message.payload),
        recipient: identityId(recipient),
        retention: retentionJson(message.retention),
        sender: identityId(sender),
        sentAt: message.sentAt,
        type: "friend-control",
        version: 1,
    });
}

/** Authenticated reuse of one control ID for different ciphertext. */
export class FriendControlIdCollisionError extends Error {
    constructor() {
        super("Authenticated friend-control ID collision");
        this.name = "FriendControlIdCollisionError";
    }
}

/**
 * Non-MLS pairwise bootstrap/control channel.
 *
 * Both peers derive the same opaque topic capability and encryption key from
 * one root secret plus the other's single public identity key. Individual
 * payloads are additionally signed by their sender identity, so possession of
 * the shared channel key does not erase authorship.
 */
export class FriendChannel {
    readonly #self: IdentityKeyPair;
    readonly #peer: IdentityPublicKey;
    readonly #now: () => number;
    readonly #encryptionKey: Uint8Array;
    readonly #topicSecretKey: Uint8Array;
    readonly #topicPublicKey: Uint8Array;

    constructor(
        self: IdentityKeyPair,
        peer: IdentityPublicKey,
        options: FriendChannelOptions = {},
    ) {
        if (equalBytes(self.publicKey, peer.publicKey)) {
            throw new Error("A friend channel requires two distinct identities");
        }
        const sharedSecret = deriveSharedSecret(self, peer);
        const salt = channelSalt(self, peer);
        let material: Uint8Array | undefined;
        try {
            material = hkdf(sha256, sharedSecret, salt, DERIVATION_INFO, 64);
            this.#self = self;
            this.#peer = { publicKey: peer.publicKey.slice() };
            this.#now = options.now ?? Date.now;
            this.#encryptionKey = material.slice(0, CONTROL_KEY_BYTES);
            this.#topicSecretKey = material.slice(CONTROL_KEY_BYTES);
            this.#topicPublicKey = ed25519.getPublicKey(this.#topicSecretKey);
        } finally {
            zeroBytes(sharedSecret);
            zeroBytes(salt);
            if (material !== undefined) {
                zeroBytes(material);
            }
        }
    }

    /** Peer identity bound to this channel. */
    get peer(): IdentityPublicKey {
        return { publicKey: this.#peer.publicKey.slice() };
    }

    /** Local public identity bound to this channel. */
    get self(): IdentityPublicKey {
        return { publicKey: this.#self.publicKey.slice() };
    }

    /** Shared opaque public key which authorizes this relay topic. */
    get topicPublicKey(): Uint8Array {
        return this.#topicPublicKey.slice();
    }

    /**
     * Export a defensive copy of the shared relay topic secret.
     *
     * The caller owns this copy and must zero it after constructing its
     * transport-specific read/write authorization.
     */
    exportTopicSecretKey(): Uint8Array {
        return this.#topicSecretKey.slice();
    }

    /** Create a new opaque control message with a random 192-bit ID. */
    createMessage(
        payload: Uint8Array,
        retention: FriendControlRetention = { kind: "durable" },
        sentAt: number = this.#now(),
    ): FriendControlMessage {
        const message: FriendControlMessage = {
            id: encodeBase64Url(randomBytes(24)),
            sentAt,
            retention,
            payload: payload.slice(),
        };
        validateControlMessage(message);
        return message;
    }

    /** Identity-sign and encrypt opaque control bytes to the peer. */
    seal(message: FriendControlMessage): FriendControlEnvelope {
        validateControlMessage(message);
        const signed = messageSignaturePayload(this.#self, this.#peer, message);
        let signature: Uint8Array | undefined;
        let plaintext: Uint8Array | undefined;
        let nonce: Uint8Array | undefined;
        let aad: Uint8Array | undefined;
        try {
            signature = signBytes(this.#self, signed);
            plaintext = utf8Encode(
                JSON.stringify({
                    id: message.id,
                    sender: identityId(this.#self),
                    recipient: identityId(this.#peer),
                    sentAt: message.sentAt,
                    retention: retentionJson(message.retention),
                    payload: encodeBase64Url(message.payload),
                    signature: encodeBase64Url(signature),
                }),
            );
            nonce = randomBytes(CONTROL_NONCE_BYTES);
            aad = envelopeAssociatedData(this.#self, this.#peer);
            return {
                version: 1,
                type: "friend-control",
                nonce: encodeBase64Url(nonce),
                ciphertext: encodeBase64Url(
                    gcm(this.#encryptionKey, nonce, aad).encrypt(plaintext),
                ),
            };
        } finally {
            zeroBytes(signed);
            if (signature !== undefined) {
                zeroBytes(signature);
            }
            if (plaintext !== undefined) {
                zeroBytes(plaintext);
            }
            if (nonce !== undefined) {
                zeroBytes(nonce);
            }
            if (aad !== undefined) {
                zeroBytes(aad);
            }
        }
    }

    /** Decrypt, bind, and verify one peer-authored control envelope. */
    open(envelope: FriendControlEnvelope, now: number = this.#now()): OpenedFriendControl {
        if (!Number.isSafeInteger(now) || now < 0) {
            throw new Error("Friend-control time must be a non-negative safe integer");
        }
        const fields = ["version", "type", "nonce", "ciphertext"];
        if (
            typeof envelope !== "object" ||
            envelope === null ||
            Array.isArray(envelope) ||
            Object.keys(envelope).length !== fields.length ||
            Object.keys(envelope).some((key) => !fields.includes(key))
        ) {
            throw new Error("Invalid friend-control envelope");
        }
        const sender = this.#peer;
        if (envelope.version !== 1 || envelope.type !== "friend-control") {
            throw new Error("Friend-control envelope is not for this channel");
        }
        if (
            typeof envelope.nonce !== "string" ||
            envelope.nonce.length !== NONCE_CHARACTERS ||
            typeof envelope.ciphertext !== "string" ||
            envelope.ciphertext.length > MAX_CONTROL_CIPHERTEXT_CHARACTERS
        ) {
            throw new Error("Invalid friend-control ciphertext");
        }
        const nonce = decodeBase64Url(envelope.nonce);
        const ciphertext = decodeBase64Url(envelope.ciphertext);
        if (
            nonce.length !== CONTROL_NONCE_BYTES ||
            ciphertext.length > MAX_CONTROL_CIPHERTEXT_BYTES
        ) {
            throw new Error("Invalid friend-control ciphertext");
        }
        const aad = envelopeAssociatedData(sender, this.#self);
        let plaintext: Uint8Array | undefined;
        try {
            plaintext = gcm(this.#encryptionKey, nonce, aad).decrypt(ciphertext);
            const decoded: unknown = JSON.parse(utf8Decode(plaintext));
            if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
                throw new Error("Invalid friend-control payload");
            }
            const value = decoded as Record<string, unknown>;
            if (
                Object.keys(value).length !== 7 ||
                typeof value.id !== "string" ||
                value.id.length !== ID_CHARACTERS ||
                typeof value.sender !== "string" ||
                value.sender.length !== PUBLIC_KEY_CHARACTERS ||
                value.sender !== identityId(sender) ||
                typeof value.recipient !== "string" ||
                value.recipient.length !== PUBLIC_KEY_CHARACTERS ||
                value.recipient !== identityId(this.#self) ||
                typeof value.sentAt !== "number" ||
                typeof value.payload !== "string" ||
                value.payload.length > MAX_CONTROL_PAYLOAD_CHARACTERS ||
                typeof value.signature !== "string" ||
                value.signature.length !== SIGNATURE_CHARACTERS ||
                typeof value.retention !== "object" ||
                value.retention === null ||
                Array.isArray(value.retention)
            ) {
                throw new Error("Invalid friend-control payload");
            }
            const retentionValue = value.retention as Record<string, unknown>;
            if (
                Object.keys(retentionValue).length !== 2 ||
                (retentionValue.kind !== "durable" && retentionValue.kind !== "temporary") ||
                (retentionValue.kind === "durable"
                    ? retentionValue.expiresAt !== null
                    : typeof retentionValue.expiresAt !== "number")
            ) {
                throw new Error("Invalid friend-control retention");
            }
            const payload = decodeBase64Url(value.payload);
            let keepPayload = false;
            try {
                const message: FriendControlMessage = {
                    id: value.id,
                    sentAt: value.sentAt,
                    retention:
                        retentionValue.kind === "durable"
                            ? { kind: "durable" }
                            : {
                                  kind: "temporary",
                                  expiresAt: retentionValue.expiresAt as number,
                              },
                    payload,
                };
                validateControlMessage(message);
                const signed = messageSignaturePayload(sender, this.#self, message);
                const signature = decodeBase64Url(value.signature);
                try {
                    if (!verifyBytes(sender, signed, signature)) {
                        throw new Error("Invalid friend-control signature");
                    }
                    if (
                        message.retention.kind === "temporary" &&
                        message.retention.expiresAt <= now
                    ) {
                        throw new Error("Friend-control message has expired");
                    }
                    keepPayload = true;
                    return { sender, message };
                } finally {
                    zeroBytes(signed);
                    zeroBytes(signature);
                }
            } finally {
                if (!keepPayload) {
                    zeroBytes(payload);
                }
            }
        } finally {
            zeroBytes(nonce);
            zeroBytes(ciphertext);
            zeroBytes(aad);
            if (plaintext !== undefined) {
                zeroBytes(plaintext);
            }
        }
    }

    /** Sign relay authorization bytes using the shared opaque topic capability. */
    signTopicBytes(bytes: Uint8Array): Uint8Array {
        return ed25519.sign(bytes, this.#topicSecretKey);
    }

    /** Verify relay authorization bytes against this channel's topic capability. */
    verifyTopicBytes(bytes: Uint8Array, signature: Uint8Array): boolean {
        try {
            return ed25519.verify(signature, bytes, this.#topicPublicKey, {
                zip215: false,
            });
        } catch {
            return false;
        }
    }

    /** Zero channel-only secrets. The root identity remains caller-owned. */
    destroy(): void {
        zeroBytes(this.#encryptionKey);
        zeroBytes(this.#topicSecretKey);
    }
}

/**
 * Accept a control envelope exactly once and commit application state with its
 * replay marker in one `MurmurStore` transaction.
 */
export async function acceptFriendControl(
    channel: FriendChannel,
    store: MurmurStore,
    envelope: FriendControlEnvelope,
    persist: PersistFriendControl,
): Promise<AcceptedFriendControl> {
    const opened = channel.open(envelope);
    const preimage = messageSignaturePayload(opened.sender, channel.self, opened.message);
    const fingerprint = hashBytes(preimage);
    const prefix = `identity/v1/${identityId(channel.self)}/friend-control-replay/`;
    const key = `${prefix}${identityId(opened.sender)}/${opened.message.id}`;
    try {
        return await store.transaction(async (transaction) => {
            const existing = await transaction.get(key);
            if (existing !== undefined) {
                if (!equalBytes(existing, fingerprint)) {
                    throw new FriendControlIdCollisionError();
                }
                return { ...opened, status: "duplicate" };
            }
            await persist(transaction, opened);
            await transaction.set(key, fingerprint);
            return { ...opened, status: "opened" };
        });
    } catch (error: unknown) {
        zeroBytes(opened.message.payload);
        throw error;
    } finally {
        zeroBytes(preimage);
        zeroBytes(fingerprint);
    }
}
