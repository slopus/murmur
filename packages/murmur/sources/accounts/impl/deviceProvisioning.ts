import { gcm } from "@noble/ciphers/aes";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import {
    importIdentityKeyPair,
    randomBytes,
    signBytes,
    validateIdentityKeyPair,
    validateIdentityPublicKey,
    verifyBytes,
    type IdentityKeyPair,
} from "../../crypto/index.js";
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
    MurmurDeviceLinkMaterial,
    MurmurDeviceLinkRequest,
    MurmurDeviceProvisioningAuthorization,
    MurmurDeviceProvisioningEnvelope,
    MurmurProvisionedAccount,
} from "../types.js";
import {
    addDeviceToRoster,
    isActiveDevice,
    parseDeviceRoster,
    serializeDeviceRoster,
    verifyDeviceRoster,
} from "./deviceRosterCodec.js";

const REQUEST_DOMAIN = utf8Encode("murmur/device-link-request/v1");
const ENVELOPE_DOMAIN = utf8Encode("murmur/device-provisioning/v1");
const PROVISIONING_INFO = utf8Encode("murmur/device-provisioning-key/v1");
const DEFAULT_LINK_TTL_MILLISECONDS = 5 * 60 * 1_000;
const MAXIMUM_KEY_PACKAGE_BYTES = 1024 * 1024;
const MAXIMUM_ENVELOPE_BYTES = 128 * 1024;

function requestTbs(request: Omit<MurmurDeviceLinkRequest, "proof">): Uint8Array {
    return new Uint8Array([
        ...REQUEST_DOMAIN,
        ...canonicalJsonBytes({
            createdAt: request.createdAt,
            deviceKey: encodeBase64Url(request.deviceKey),
            ephemeralKey: encodeBase64Url(request.ephemeralKey),
            expiresAt: request.expiresAt,
            keyPackage: encodeBase64Url(request.keyPackage),
            requestId: encodeBase64Url(request.requestId),
            version: 1,
        }),
    ]);
}

function envelopeTbs(envelope: Omit<MurmurDeviceProvisioningEnvelope, "signature">): Uint8Array {
    return new Uint8Array([
        ...ENVELOPE_DOMAIN,
        ...canonicalJsonBytes({
            authorDeviceKey: encodeBase64Url(envelope.authorDeviceKey),
            ciphertext: encodeBase64Url(envelope.ciphertext),
            createdAt: envelope.createdAt,
            ephemeralKey: encodeBase64Url(envelope.ephemeralKey),
            expiresAt: envelope.expiresAt,
            nonce: encodeBase64Url(envelope.nonce),
            requestId: encodeBase64Url(envelope.requestId),
            version: 1,
        }),
    ]);
}

function requestHash(request: MurmurDeviceLinkRequest): Uint8Array {
    return sha256(new Uint8Array([...requestTbs(request), ...request.proof]));
}

function provisioningAad(request: MurmurDeviceLinkRequest): Uint8Array {
    return new Uint8Array([...ENVELOPE_DOMAIN, ...requestHash(request)]);
}

function deriveProvisioningKey(
    sharedSecret: Uint8Array,
    request: MurmurDeviceLinkRequest,
    senderEphemeralKey: Uint8Array,
): Uint8Array {
    return hkdf(
        sha256,
        sharedSecret,
        new Uint8Array([...request.ephemeralKey, ...senderEphemeralKey]),
        new Uint8Array([...PROVISIONING_INFO, ...requestHash(request)]),
        32,
    );
}

function assertCurrentRequest(request: MurmurDeviceLinkRequest, now: number): void {
    validateIdentityPublicKey({ publicKey: request.deviceKey });
    if (
        request.version !== 1 ||
        request.requestId.length !== 32 ||
        !Number.isSafeInteger(request.createdAt) ||
        !Number.isSafeInteger(request.expiresAt) ||
        request.createdAt < 0 ||
        request.expiresAt <= request.createdAt ||
        request.expiresAt - request.createdAt > DEFAULT_LINK_TTL_MILLISECONDS ||
        now < request.createdAt ||
        now >= request.expiresAt ||
        request.ephemeralKey.length !== 32 ||
        request.keyPackage.length < 1 ||
        request.keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES ||
        request.proof.length !== 64 ||
        !verifyBytes({ publicKey: request.deviceKey }, requestTbs(request), request.proof)
    ) {
        throw new Error("Invalid or expired device-link request");
    }
    const validationSecret = new Uint8Array(32).fill(1);
    let validationShared: Uint8Array | undefined;
    try {
        validationShared = x25519.getSharedSecret(validationSecret, request.ephemeralKey);
    } catch {
        throw new Error("Invalid device-link ephemeral key");
    } finally {
        zeroBytes(validationSecret);
        if (validationShared !== undefined) zeroBytes(validationShared);
    }
}

function bytesField(value: unknown, exactLength: number | null, name: string): Uint8Array {
    if (typeof value !== "string") throw new Error(`Invalid ${name}`);
    const result = decodeBase64Url(value);
    if (
        (exactLength !== null && result.length !== exactLength) ||
        encodeBase64Url(result) !== value
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return result;
}

function parseObject(
    value: Uint8Array,
    fields: readonly string[],
    name: string,
): Record<string, unknown> {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(value)) as unknown;
    } catch {
        throw new Error(`Invalid ${name}`);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error(`Invalid ${name}`);
    }
    const input = parsed as Record<string, unknown>;
    if (
        fields.some((field) => !Object.hasOwn(input, field)) ||
        Object.keys(input).some((field) => !fields.includes(field))
    ) {
        throw new Error(`Invalid ${name}`);
    }
    return input;
}

/** Serialize one device-link request for out-of-band transfer. */
export function serializeDeviceLinkRequest(request: MurmurDeviceLinkRequest): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        requestId: encodeBase64Url(request.requestId),
        createdAt: request.createdAt,
        expiresAt: request.expiresAt,
        ephemeralKey: encodeBase64Url(request.ephemeralKey),
        deviceKey: encodeBase64Url(request.deviceKey),
        keyPackage: encodeBase64Url(request.keyPackage),
        proof: encodeBase64Url(request.proof),
    });
}

/** Parse and time-validate one out-of-band device-link request. */
export function parseDeviceLinkRequest(
    value: Uint8Array,
    now: number = Date.now(),
): MurmurDeviceLinkRequest {
    if (value.length < 1 || value.length > 2 * MAXIMUM_KEY_PACKAGE_BYTES) {
        throw new Error("Invalid device-link request");
    }
    const input = parseObject(
        value,
        [
            "version",
            "requestId",
            "createdAt",
            "expiresAt",
            "ephemeralKey",
            "deviceKey",
            "keyPackage",
            "proof",
        ],
        "device-link request",
    );
    if (
        input.version !== 1 ||
        typeof input.createdAt !== "number" ||
        typeof input.expiresAt !== "number"
    ) {
        throw new Error("Invalid device-link request");
    }
    const request: MurmurDeviceLinkRequest = Object.freeze({
        version: 1,
        requestId: bytesField(input.requestId, 32, "link request ID"),
        createdAt: input.createdAt,
        expiresAt: input.expiresAt,
        ephemeralKey: bytesField(input.ephemeralKey, 32, "link ephemeral key"),
        deviceKey: bytesField(input.deviceKey, 32, "link device key"),
        keyPackage: bytesField(input.keyPackage, null, "link KeyPackage"),
        proof: bytesField(input.proof, 64, "link proof"),
    });
    assertCurrentRequest(request, now);
    return request;
}

/** Serialize one provisioning envelope for out-of-band transfer. */
export function serializeProvisioningEnvelope(
    envelope: MurmurDeviceProvisioningEnvelope,
): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        requestId: encodeBase64Url(envelope.requestId),
        createdAt: envelope.createdAt,
        expiresAt: envelope.expiresAt,
        authorDeviceKey: encodeBase64Url(envelope.authorDeviceKey),
        ephemeralKey: encodeBase64Url(envelope.ephemeralKey),
        nonce: encodeBase64Url(envelope.nonce),
        ciphertext: encodeBase64Url(envelope.ciphertext),
        signature: encodeBase64Url(envelope.signature),
    });
}

/** Parse one out-of-band provisioning envelope without decrypting it. */
export function parseProvisioningEnvelope(value: Uint8Array): MurmurDeviceProvisioningEnvelope {
    if (value.length < 1 || value.length > 2 * MAXIMUM_ENVELOPE_BYTES) {
        throw new Error("Invalid provisioning envelope");
    }
    const input = parseObject(
        value,
        [
            "version",
            "requestId",
            "createdAt",
            "expiresAt",
            "authorDeviceKey",
            "ephemeralKey",
            "nonce",
            "ciphertext",
            "signature",
        ],
        "provisioning envelope",
    );
    if (
        input.version !== 1 ||
        typeof input.createdAt !== "number" ||
        typeof input.expiresAt !== "number"
    ) {
        throw new Error("Invalid provisioning envelope");
    }
    return Object.freeze({
        version: 1,
        requestId: bytesField(input.requestId, 32, "envelope request ID"),
        createdAt: input.createdAt,
        expiresAt: input.expiresAt,
        authorDeviceKey: bytesField(input.authorDeviceKey, 32, "envelope author key"),
        ephemeralKey: bytesField(input.ephemeralKey, 32, "envelope ephemeral key"),
        nonce: bytesField(input.nonce, 12, "envelope nonce"),
        ciphertext: bytesField(input.ciphertext, null, "envelope ciphertext"),
        signature: bytesField(input.signature, 64, "envelope signature"),
    });
}

/** Serialize retained link material, including its ephemeral secret, for storage. */
export function serializeDeviceLinkMaterial(material: MurmurDeviceLinkMaterial): Uint8Array {
    return canonicalJsonBytes({
        version: 1,
        request: encodeBase64Url(serializeDeviceLinkRequest(material.request)),
        ephemeralSecretKey: encodeBase64Url(material.ephemeralSecretKey),
    });
}

/** Restore retained link material from durable storage without expiry checks. */
export function parseDeviceLinkMaterial(
    value: Uint8Array,
    now: number = Date.now(),
): MurmurDeviceLinkMaterial {
    const input = parseObject(
        value,
        ["version", "request", "ephemeralSecretKey"],
        "device-link material",
    );
    if (input.version !== 1) throw new Error("Invalid device-link material");
    return Object.freeze({
        request: parseDeviceLinkRequest(bytesField(input.request, null, "link request"), now),
        ephemeralSecretKey: bytesField(input.ephemeralSecretKey, 32, "link ephemeral secret"),
    });
}

/** Create short-lived URI material and retain the matching ephemeral secret. */
export function createDeviceLinkMaterial(
    device: IdentityKeyPair,
    keyPackage: Uint8Array,
    now: number = Date.now(),
    ttlMilliseconds: number = DEFAULT_LINK_TTL_MILLISECONDS,
): MurmurDeviceLinkMaterial {
    validateIdentityKeyPair(device);
    if (
        !Number.isSafeInteger(now) ||
        now < 0 ||
        !Number.isSafeInteger(ttlMilliseconds) ||
        ttlMilliseconds < 1 ||
        ttlMilliseconds > DEFAULT_LINK_TTL_MILLISECONDS ||
        keyPackage.length < 1 ||
        keyPackage.length > MAXIMUM_KEY_PACKAGE_BYTES
    ) {
        throw new Error("Invalid device-link request inputs");
    }
    const ephemeralSecretKey = randomBytes(32);
    const unsigned: Omit<MurmurDeviceLinkRequest, "proof"> = {
        version: 1,
        requestId: randomBytes(32),
        createdAt: now,
        expiresAt: now + ttlMilliseconds,
        ephemeralKey: x25519.getPublicKey(ephemeralSecretKey),
        deviceKey: device.publicKey.slice(),
        keyPackage: keyPackage.slice(),
    };
    return Object.freeze({
        request: Object.freeze({ ...unsigned, proof: signBytes(device, requestTbs(unsigned)) }),
        ephemeralSecretKey,
    });
}

/** Verify a new-device proof, sign a roster child, and encrypt account custody. */
export function authorizeDeviceProvisioning(authorization: MurmurDeviceProvisioningAuthorization): {
    readonly envelope: MurmurDeviceProvisioningEnvelope;
    readonly roster: ReturnType<typeof addDeviceToRoster>;
} {
    const now = authorization.now ?? Date.now();
    assertCurrentRequest(authorization.request, now);
    validateIdentityKeyPair(authorization.account);
    validateIdentityKeyPair(authorization.authorDevice);
    if (
        !verifyDeviceRoster(authorization.roster) ||
        !equalBytes(authorization.roster.accountKey, authorization.account.publicKey) ||
        !isActiveDevice(authorization.roster, authorization.authorDevice.publicKey)
    ) {
        throw new Error("Provisioning author is not active in the account roster");
    }
    const roster = addDeviceToRoster(
        authorization.roster,
        authorization.account,
        authorization.authorDevice,
        authorization.request.deviceKey,
        now,
        authorization.request.requestId.slice(0, 16),
    );
    const plaintext = canonicalJsonBytes({
        accountSecretKey: encodeBase64Url(authorization.account.secretKey),
        requestHash: encodeBase64Url(requestHash(authorization.request)),
        roster: encodeBase64Url(serializeDeviceRoster(roster)),
        version: 1,
    });
    const senderSecretKey = randomBytes(32);
    let sharedSecret: Uint8Array | undefined;
    let key: Uint8Array | undefined;
    try {
        const ephemeralKey = x25519.getPublicKey(senderSecretKey);
        sharedSecret = x25519.getSharedSecret(senderSecretKey, authorization.request.ephemeralKey);
        key = deriveProvisioningKey(sharedSecret, authorization.request, ephemeralKey);
        const nonce = randomBytes(12);
        const unsigned: Omit<MurmurDeviceProvisioningEnvelope, "signature"> = {
            version: 1,
            requestId: authorization.request.requestId.slice(),
            createdAt: now,
            expiresAt: authorization.request.expiresAt,
            authorDeviceKey: authorization.authorDevice.publicKey.slice(),
            ephemeralKey,
            nonce,
            ciphertext: gcm(key, nonce, provisioningAad(authorization.request)).encrypt(plaintext),
        };
        return Object.freeze({
            roster,
            envelope: Object.freeze({
                ...unsigned,
                signature: signBytes(authorization.authorDevice, envelopeTbs(unsigned)),
            }),
        });
    } finally {
        zeroBytes(plaintext);
        zeroBytes(senderSecretKey);
        if (sharedSecret !== undefined) zeroBytes(sharedSecret);
        if (key !== undefined) zeroBytes(key);
    }
}

/** Decrypt and authenticate one transcript-bound provisioning response. */
export function completeDeviceProvisioning(
    material: MurmurDeviceLinkMaterial,
    envelope: MurmurDeviceProvisioningEnvelope,
    now: number = Date.now(),
): MurmurProvisionedAccount {
    assertCurrentRequest(material.request, now);
    if (
        envelope.version !== 1 ||
        !equalBytes(envelope.requestId, material.request.requestId) ||
        envelope.createdAt < material.request.createdAt ||
        envelope.createdAt > now ||
        envelope.expiresAt !== material.request.expiresAt ||
        now >= envelope.expiresAt ||
        envelope.ephemeralKey.length !== 32 ||
        envelope.nonce.length !== 12 ||
        envelope.ciphertext.length < 16 ||
        envelope.ciphertext.length > MAXIMUM_ENVELOPE_BYTES ||
        envelope.signature.length !== 64
    ) {
        throw new Error("Invalid or expired provisioning envelope");
    }
    validateIdentityPublicKey({ publicKey: envelope.authorDeviceKey });
    if (
        !verifyBytes(
            { publicKey: envelope.authorDeviceKey },
            envelopeTbs(envelope),
            envelope.signature,
        )
    ) {
        throw new Error("Invalid provisioning envelope signature");
    }
    const sharedSecret = x25519.getSharedSecret(material.ephemeralSecretKey, envelope.ephemeralKey);
    const key = deriveProvisioningKey(sharedSecret, material.request, envelope.ephemeralKey);
    let plaintext: Uint8Array | undefined;
    try {
        plaintext = gcm(key, envelope.nonce, provisioningAad(material.request)).decrypt(
            envelope.ciphertext,
        );
        if (plaintext.length < 1 || plaintext.length > MAXIMUM_ENVELOPE_BYTES) {
            throw new Error("Invalid provisioning plaintext");
        }
        const parsed = JSON.parse(utf8Decode(plaintext)) as unknown;
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Invalid provisioning plaintext");
        }
        const input = parsed as Record<string, unknown>;
        if (
            input.version !== 1 ||
            typeof input.accountSecretKey !== "string" ||
            typeof input.requestHash !== "string" ||
            typeof input.roster !== "string" ||
            Object.keys(input).some(
                (field) =>
                    !["accountSecretKey", "requestHash", "roster", "version"].includes(field),
            )
        ) {
            throw new Error("Invalid provisioning plaintext");
        }
        const accountSecretKey = decodeBase64Url(input.accountSecretKey);
        try {
            if (
                accountSecretKey.length !== 32 ||
                !equalBytes(decodeBase64Url(input.requestHash), requestHash(material.request))
            ) {
                throw new Error("Provisioning transcript mismatch");
            }
            const account = importIdentityKeyPair(accountSecretKey);
            const roster = parseDeviceRoster(decodeBase64Url(input.roster));
            if (
                !equalBytes(roster.accountKey, account.publicKey) ||
                !equalBytes(roster.authorDeviceKey, envelope.authorDeviceKey) ||
                !isActiveDevice(roster, material.request.deviceKey)
            ) {
                zeroBytes(account.secretKey);
                throw new Error("Provisioned account does not authorize this device");
            }
            return Object.freeze({ account, roster });
        } finally {
            zeroBytes(accountSecretKey);
        }
    } catch {
        throw new Error("Invalid provisioning envelope");
    } finally {
        zeroBytes(sharedSecret);
        zeroBytes(key);
        if (plaintext !== undefined) zeroBytes(plaintext);
    }
}
