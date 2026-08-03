import {
    canonicalJson,
    canonicalJsonBytes,
    decodeBase64Url,
    encodeBase64Url,
    equalBytes,
    hashBytes,
    identityId,
    signBytes,
    utf8Decode,
    utf8Encode,
    validateFileDescriptor,
    verifyBytes,
    type EncryptedFileDescriptor,
    type IdentityKeyPair,
    type IdentityPublicKeys,
    type JsonValue,
} from "@slopus/murmur";
import type {
    SharedSessionControl,
    SharedSessionEntry,
    SharedSessionEntryInput,
    SharedSessionHistoryPageDescriptor,
    SharedSessionMemberGrant,
    SharedSessionPost,
    SharedSessionState,
} from "../types.js";
import {
    MAX_SHARED_SESSION_CONTROL_BYTES,
    MAX_SHARED_SESSION_ENTRY_BYTES,
    MAX_SHARED_SESSION_HISTORY_PAGE_BYTES,
    MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES,
    MAX_SHARED_SESSION_MEMBERS,
    MAX_SHARED_SESSION_OFFER_PAGES,
    MAX_SHARED_SESSION_POST_BYTES,
    MAX_SHARED_SESSION_SHARE_ID_BYTES,
    SharedSessionProtocolError,
} from "../types.js";

const OWNER_FRAME_CONTEXT = "murmur/shared-session/owner-frame/v1";
const INVITATION_CONTEXT = "murmur/shared-session/invitation/v1";
const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPAQUE_ID_PATTERN = /^[A-Za-z0-9_-][A-Za-z0-9._:-]{0,255}$/;

export interface SharedSessionEntryFrame {
    readonly version: 1;
    readonly kind: "entry";
    readonly shareId: string;
    readonly groupId: string;
    readonly ownerId: string;
    readonly entry: SharedSessionEntry;
    readonly signature: string;
}

export interface SharedSessionStateFrame {
    readonly version: 1;
    readonly kind: "state";
    readonly shareId: string;
    readonly groupId: string;
    readonly ownerId: string;
    readonly state: SharedSessionState;
    readonly signature: string;
}

export interface SharedSessionPostFrame {
    readonly version: 1;
    readonly kind: "post";
    readonly shareId: string;
    readonly groupId: string;
    readonly postId: string;
    readonly grantEpoch: number;
    readonly timestamp: number;
    readonly text: string;
}

export interface SharedSessionControlFrame {
    readonly version: 1;
    readonly kind: "control";
    readonly shareId: string;
    readonly groupId: string;
    readonly controlId: string;
    readonly grantEpoch: number;
    readonly timestamp: number;
    readonly payload: JsonValue;
}

export type SharedSessionFrame =
    | SharedSessionEntryFrame
    | SharedSessionStateFrame
    | SharedSessionPostFrame
    | SharedSessionControlFrame;

type UnsignedOwnerFrame =
    | Omit<SharedSessionEntryFrame, "signature">
    | Omit<SharedSessionStateFrame, "signature">;
type JsonObject = { readonly [key: string]: JsonValue };

export interface SharedSessionHistoryOffer {
    readonly version: 1;
    readonly shareId: string;
    readonly groupId: string;
    readonly throughSequence: number;
    readonly pages: readonly SharedSessionHistoryPageDescriptor[];
    readonly previous?: EncryptedFileDescriptor;
}

export interface DecodedSharedSessionInvitation {
    readonly version: 1;
    readonly shareId: string;
    readonly groupId: Uint8Array;
    readonly ownerId: string;
    readonly recipientId: string;
    readonly state: SharedSessionState;
    readonly grant: SharedSessionMemberGrant;
    readonly welcome: Uint8Array;
    readonly tree: Uint8Array;
    readonly keyPackageReference: Uint8Array;
    readonly commitFingerprint: Uint8Array;
    readonly historyOffer?: EncryptedFileDescriptor;
    readonly signature: Uint8Array;
}

function protocolError(message: string, options?: ErrorOptions): SharedSessionProtocolError {
    return new SharedSessionProtocolError("invalid-frame", message, options);
}

function exactRecord(
    value: unknown,
    fields: readonly string[],
    name: string,
): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw protocolError(`Invalid ${name}`);
    }
    const keys = Object.keys(value);
    if (keys.length !== fields.length || keys.some((key) => !fields.includes(key))) {
        throw protocolError(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function optionalRecord(
    value: unknown,
    required: readonly string[],
    optional: readonly string[],
    name: string,
): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw protocolError(`Invalid ${name}`);
    }
    const keys = Object.keys(value);
    if (
        required.some((key) => !keys.includes(key)) ||
        keys.some((key) => !required.includes(key) && !optional.includes(key))
    ) {
        throw protocolError(`Invalid ${name}`);
    }
    return value as Record<string, unknown>;
}

function isJsonValue(value: unknown, depth: number = 0): value is JsonValue {
    if (depth > 64) {
        return false;
    }
    if (
        value === null ||
        typeof value === "boolean" ||
        typeof value === "string" ||
        (typeof value === "number" && Number.isFinite(value))
    ) {
        return true;
    }
    if (Array.isArray(value)) {
        return value.every((entry) => isJsonValue(entry, depth + 1));
    }
    return (
        typeof value === "object" &&
        value !== null &&
        Object.values(value).every((entry) => isJsonValue(entry, depth + 1))
    );
}

export function validateSharedSessionShareId(shareId: string): void {
    const bytes = utf8Encode(shareId);
    if (
        bytes.length === 0 ||
        bytes.length > MAX_SHARED_SESSION_SHARE_ID_BYTES ||
        !OPAQUE_ID_PATTERN.test(shareId)
    ) {
        throw new Error("Invalid shared-session shareId");
    }
}

export function validateSharedSessionEventId(eventId: string): void {
    if (!UUID_V7_PATTERN.test(eventId)) {
        throw new Error("Shared-session event ID must be a lowercase UUIDv7");
    }
}

function validateTimestamp(timestamp: number): void {
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
        throw new Error("Invalid shared-session timestamp");
    }
}

function validateSequence(sequence: number, allowZero: boolean = false): void {
    if (
        !Number.isSafeInteger(sequence) ||
        sequence < (allowZero ? 0 : 1) ||
        sequence > Number.MAX_SAFE_INTEGER
    ) {
        throw new Error("Invalid shared-session sequence");
    }
}

export function contentHashForPayload(payload: JsonValue): string {
    const bytes = canonicalJsonBytes(payload);
    if (bytes.length > MAX_SHARED_SESSION_ENTRY_BYTES) {
        throw new Error("Shared-session entry payload exceeds its canonical JSON bound");
    }
    return encodeBase64Url(hashBytes(bytes));
}

export function createSharedSessionEntry(
    shareId: string,
    input: SharedSessionEntryInput,
): SharedSessionEntry {
    validateSharedSessionShareId(shareId);
    validateSequence(input.shareSequence);
    validateSharedSessionEventId(input.shareEventId);
    validateTimestamp(input.timestamp);
    if (!isJsonValue(input.payload)) {
        throw new Error("Shared-session payload is not canonical JSON data");
    }
    return {
        shareId,
        shareSequence: input.shareSequence,
        shareEventId: input.shareEventId,
        contentHash: contentHashForPayload(input.payload),
        timestamp: input.timestamp,
        payload: input.payload,
    };
}

function serializeGrant(grant: SharedSessionMemberGrant): JsonValue {
    if (
        !OPAQUE_ID_PATTERN.test(grant.shareMemberId) ||
        !/^[A-Za-z0-9_-]{43}$/.test(grant.peerId) ||
        !Number.isSafeInteger(grant.grantEpoch) ||
        grant.grantEpoch < 1 ||
        (grant.status !== "active" && grant.status !== "ended")
    ) {
        throw new Error("Invalid shared-session member grant");
    }
    return {
        grantEpoch: grant.grantEpoch,
        peerId: grant.peerId,
        shareMemberId: grant.shareMemberId,
        status: grant.status,
    };
}

function deserializeGrant(value: unknown): SharedSessionMemberGrant {
    const grant = exactRecord(
        value,
        ["grantEpoch", "peerId", "shareMemberId", "status"],
        "shared-session member grant",
    );
    if (
        typeof grant.grantEpoch !== "number" ||
        typeof grant.peerId !== "string" ||
        typeof grant.shareMemberId !== "string" ||
        (grant.status !== "active" && grant.status !== "ended")
    ) {
        throw protocolError("Invalid shared-session member grant");
    }
    const result: SharedSessionMemberGrant = {
        grantEpoch: grant.grantEpoch,
        peerId: grant.peerId,
        shareMemberId: grant.shareMemberId,
        status: grant.status,
    };
    serializeGrant(result);
    return result;
}

export function sharedSessionStateToJson(state: SharedSessionState): JsonValue {
    validateSharedSessionShareId(state.shareId);
    if (
        !/^[A-Za-z0-9_-]{43}$/.test(state.groupId) ||
        !/^[A-Za-z0-9_-]{43}$/.test(state.ownerId) ||
        !Number.isSafeInteger(state.stateSequence) ||
        state.stateSequence < 0 ||
        !["active", "stopped", "terminated"].includes(state.status) ||
        state.members.length > MAX_SHARED_SESSION_MEMBERS
    ) {
        throw new Error("Invalid shared-session state");
    }
    const grants = state.members.map(serializeGrant);
    const memberIds = new Set(state.members.map((member) => member.shareMemberId));
    const activePeers = new Set(
        state.members.filter((member) => member.status === "active").map((member) => member.peerId),
    );
    if (
        memberIds.size !== state.members.length ||
        activePeers.size !== state.members.filter((member) => member.status === "active").length
    ) {
        throw new Error("Duplicate shared-session member grant");
    }
    return {
        groupId: state.groupId,
        members: grants,
        ownerId: state.ownerId,
        shareId: state.shareId,
        stateSequence: state.stateSequence,
        status: state.status,
    };
}

export function sharedSessionStateFromJson(value: unknown): SharedSessionState {
    const state = exactRecord(
        value,
        ["groupId", "members", "ownerId", "shareId", "stateSequence", "status"],
        "shared-session state",
    );
    if (
        typeof state.groupId !== "string" ||
        !Array.isArray(state.members) ||
        typeof state.ownerId !== "string" ||
        typeof state.shareId !== "string" ||
        typeof state.stateSequence !== "number" ||
        (state.status !== "active" && state.status !== "stopped" && state.status !== "terminated")
    ) {
        throw protocolError("Invalid shared-session state");
    }
    const result: SharedSessionState = {
        groupId: state.groupId,
        members: state.members.map(deserializeGrant),
        ownerId: state.ownerId,
        shareId: state.shareId,
        stateSequence: state.stateSequence,
        status: state.status,
    };
    sharedSessionStateToJson(result);
    return result;
}

export function sharedSessionEntryToJson(entry: SharedSessionEntry): JsonValue {
    const validated = createSharedSessionEntry(entry.shareId, entry);
    if (validated.contentHash !== entry.contentHash) {
        throw new Error("Shared-session entry content hash mismatch");
    }
    return {
        contentHash: entry.contentHash,
        payload: entry.payload,
        shareEventId: entry.shareEventId,
        shareId: entry.shareId,
        shareSequence: entry.shareSequence,
        timestamp: entry.timestamp,
    };
}

export function sharedSessionEntryFromJson(value: unknown): SharedSessionEntry {
    const entry = exactRecord(
        value,
        ["contentHash", "payload", "shareEventId", "shareId", "shareSequence", "timestamp"],
        "shared-session entry",
    );
    if (
        typeof entry.contentHash !== "string" ||
        !isJsonValue(entry.payload) ||
        typeof entry.shareEventId !== "string" ||
        typeof entry.shareId !== "string" ||
        typeof entry.shareSequence !== "number" ||
        typeof entry.timestamp !== "number"
    ) {
        throw protocolError("Invalid shared-session entry");
    }
    const result: SharedSessionEntry = {
        contentHash: entry.contentHash,
        payload: entry.payload,
        shareEventId: entry.shareEventId,
        shareId: entry.shareId,
        shareSequence: entry.shareSequence,
        timestamp: entry.timestamp,
    };
    sharedSessionEntryToJson(result);
    return result;
}

function ownerFrameValue(frame: UnsignedOwnerFrame): JsonObject {
    return frame.kind === "entry"
        ? {
              entry: sharedSessionEntryToJson(frame.entry),
              groupId: frame.groupId,
              kind: frame.kind,
              ownerId: frame.ownerId,
              shareId: frame.shareId,
              version: frame.version,
          }
        : {
              groupId: frame.groupId,
              kind: frame.kind,
              ownerId: frame.ownerId,
              shareId: frame.shareId,
              state: sharedSessionStateToJson(frame.state),
              version: frame.version,
          };
}

function ownerSigningValue(frame: UnsignedOwnerFrame): JsonValue {
    return {
        context: OWNER_FRAME_CONTEXT,
        frame: ownerFrameValue(frame),
    };
}

export function encodeSharedSessionOwnerEntryFrame(options: {
    readonly identity: IdentityKeyPair;
    readonly groupId: Uint8Array;
    readonly entry: SharedSessionEntry;
}): Uint8Array {
    const frame = {
        version: 1 as const,
        kind: "entry" as const,
        shareId: options.entry.shareId,
        groupId: encodeBase64Url(options.groupId),
        ownerId: identityId(options.identity),
        entry: options.entry,
    };
    const signature = signBytes(options.identity, canonicalJsonBytes(ownerSigningValue(frame)));
    return canonicalJsonBytes({
        ...ownerFrameValue(frame),
        signature: encodeBase64Url(signature),
    });
}

export function encodeSharedSessionOwnerStateFrame(options: {
    readonly identity: IdentityKeyPair;
    readonly groupId: Uint8Array;
    readonly state: SharedSessionState;
}): Uint8Array {
    const frame = {
        version: 1 as const,
        kind: "state" as const,
        shareId: options.state.shareId,
        groupId: encodeBase64Url(options.groupId),
        ownerId: identityId(options.identity),
        state: options.state,
    };
    const signature = signBytes(options.identity, canonicalJsonBytes(ownerSigningValue(frame)));
    return canonicalJsonBytes({
        ...ownerFrameValue(frame),
        signature: encodeBase64Url(signature),
    });
}

export function encodeSharedSessionPostFrame(
    groupId: Uint8Array,
    post: Omit<SharedSessionPost, "authenticatedPeerId" | "shareMemberId">,
): Uint8Array {
    validateSharedSessionShareId(post.shareId);
    if (
        !OPAQUE_ID_PATTERN.test(post.postId) ||
        !Number.isSafeInteger(post.grantEpoch) ||
        post.grantEpoch < 1 ||
        utf8Encode(post.text).length > MAX_SHARED_SESSION_POST_BYTES
    ) {
        throw new Error("Invalid shared-session friend post");
    }
    validateTimestamp(post.timestamp);
    return canonicalJsonBytes({
        grantEpoch: post.grantEpoch,
        groupId: encodeBase64Url(groupId),
        kind: "post",
        postId: post.postId,
        shareId: post.shareId,
        text: post.text,
        timestamp: post.timestamp,
        version: 1,
    });
}

/**
 * Encode one friend control frame.
 *
 * Control carries opaque canonical JSON exactly as an owner transcript entry
 * does, so an application never has to smuggle structured negotiation through
 * conversational text and filter it back out again.
 */
export function encodeSharedSessionControlFrame(
    groupId: Uint8Array,
    control: Omit<SharedSessionControl, "authenticatedPeerId" | "shareMemberId">,
): Uint8Array {
    validateSharedSessionShareId(control.shareId);
    if (
        !OPAQUE_ID_PATTERN.test(control.controlId) ||
        !Number.isSafeInteger(control.grantEpoch) ||
        control.grantEpoch < 1 ||
        !isJsonValue(control.payload)
    ) {
        throw new Error("Invalid shared-session friend control");
    }
    validateTimestamp(control.timestamp);
    const payload = canonicalJsonBytes(control.payload);
    if (payload.length > MAX_SHARED_SESSION_CONTROL_BYTES) {
        throw new Error("Shared-session control payload exceeds its canonical JSON bound");
    }
    return canonicalJsonBytes({
        controlId: control.controlId,
        grantEpoch: control.grantEpoch,
        groupId: encodeBase64Url(groupId),
        kind: "control",
        payload: control.payload,
        shareId: control.shareId,
        timestamp: control.timestamp,
        version: 1,
    });
}

export function decodeSharedSessionFrame(
    bytes: Uint8Array,
    owner: IdentityPublicKeys,
): SharedSessionFrame {
    let parsed: unknown;
    try {
        parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    } catch (error: unknown) {
        throw protocolError("Invalid shared-session frame JSON", {
            cause: error,
        });
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw protocolError("Invalid shared-session frame");
    }
    const kind = (parsed as Record<string, unknown>).kind;
    if (kind === "post") {
        const value = exactRecord(
            parsed,
            ["grantEpoch", "groupId", "kind", "postId", "shareId", "text", "timestamp", "version"],
            "shared-session post frame",
        );
        if (
            value.version !== 1 ||
            typeof value.groupId !== "string" ||
            typeof value.shareId !== "string" ||
            typeof value.postId !== "string" ||
            typeof value.grantEpoch !== "number" ||
            typeof value.timestamp !== "number" ||
            typeof value.text !== "string"
        ) {
            throw protocolError("Invalid shared-session post frame");
        }
        const frame: SharedSessionPostFrame = {
            version: 1,
            kind: "post",
            groupId: value.groupId,
            shareId: value.shareId,
            postId: value.postId,
            grantEpoch: value.grantEpoch,
            timestamp: value.timestamp,
            text: value.text,
        };
        let canonical: Uint8Array;
        try {
            canonical = encodeSharedSessionPostFrame(decodeBase64Url(frame.groupId), frame);
        } catch (error: unknown) {
            throw protocolError("Invalid shared-session post frame", { cause: error });
        }
        if (!equalBytes(canonical, bytes)) {
            throw protocolError("Non-canonical shared-session post frame");
        }
        return frame;
    }
    if (kind === "control") {
        const value = exactRecord(
            parsed,
            [
                "controlId",
                "grantEpoch",
                "groupId",
                "kind",
                "payload",
                "shareId",
                "timestamp",
                "version",
            ],
            "shared-session control frame",
        );
        if (
            value.version !== 1 ||
            typeof value.groupId !== "string" ||
            typeof value.shareId !== "string" ||
            typeof value.controlId !== "string" ||
            typeof value.grantEpoch !== "number" ||
            typeof value.timestamp !== "number" ||
            !isJsonValue(value.payload)
        ) {
            throw protocolError("Invalid shared-session control frame");
        }
        const frame: SharedSessionControlFrame = {
            version: 1,
            kind: "control",
            groupId: value.groupId,
            shareId: value.shareId,
            controlId: value.controlId,
            grantEpoch: value.grantEpoch,
            timestamp: value.timestamp,
            payload: value.payload,
        };
        let canonical: Uint8Array;
        try {
            canonical = encodeSharedSessionControlFrame(decodeBase64Url(frame.groupId), frame);
        } catch (error: unknown) {
            throw protocolError("Invalid shared-session control frame", { cause: error });
        }
        if (!equalBytes(canonical, bytes)) {
            throw protocolError("Non-canonical shared-session control frame");
        }
        return frame;
    }
    const value = exactRecord(
        parsed,
        kind === "entry"
            ? ["entry", "groupId", "kind", "ownerId", "shareId", "signature", "version"]
            : ["groupId", "kind", "ownerId", "shareId", "signature", "state", "version"],
        "shared-session owner frame",
    );
    if (
        value.version !== 1 ||
        (kind !== "entry" && kind !== "state") ||
        typeof value.groupId !== "string" ||
        typeof value.ownerId !== "string" ||
        typeof value.shareId !== "string" ||
        typeof value.signature !== "string"
    ) {
        throw protocolError("Invalid shared-session owner frame");
    }
    const signature = decodeBase64Url(value.signature);
    const unsigned =
        kind === "entry"
            ? ({
                  version: 1,
                  kind,
                  groupId: value.groupId,
                  ownerId: value.ownerId,
                  shareId: value.shareId,
                  entry: sharedSessionEntryFromJson(value.entry),
              } satisfies Omit<SharedSessionEntryFrame, "signature">)
            : ({
                  version: 1,
                  kind,
                  groupId: value.groupId,
                  ownerId: value.ownerId,
                  shareId: value.shareId,
                  state: sharedSessionStateFromJson(value.state),
              } satisfies Omit<SharedSessionStateFrame, "signature">);
    const inner = unsigned.kind === "entry" ? unsigned.entry : unsigned.state;
    if (
        value.ownerId !== identityId(owner) ||
        inner.shareId !== unsigned.shareId ||
        (unsigned.kind === "state" &&
            (unsigned.state.groupId !== unsigned.groupId ||
                unsigned.state.ownerId !== unsigned.ownerId)) ||
        !verifyBytes(owner, canonicalJsonBytes(ownerSigningValue(unsigned)), signature) ||
        canonicalJson(parsed as JsonValue) !== utf8Decode(bytes)
    ) {
        throw new SharedSessionProtocolError(
            "owner-authorization",
            "Invalid shared-session owner frame signature",
        );
    }
    return { ...unsigned, signature: value.signature } as SharedSessionFrame;
}

export function sharedSessionFileToJson(file: EncryptedFileDescriptor): JsonValue {
    validateFileDescriptor(file);
    return {
        version: 1,
        blobId: file.blobId,
        key: encodeBase64Url(file.key),
        nonce: encodeBase64Url(file.nonce),
        name: file.name,
        mediaType: file.mediaType,
        plaintextBytes: file.plaintextBytes,
    };
}

export function sharedSessionFileFromJson(value: unknown): EncryptedFileDescriptor {
    const file = exactRecord(
        value,
        ["blobId", "key", "mediaType", "name", "nonce", "plaintextBytes", "version"],
        "shared-session encrypted file descriptor",
    );
    if (
        file.version !== 1 ||
        typeof file.blobId !== "string" ||
        typeof file.key !== "string" ||
        typeof file.nonce !== "string" ||
        typeof file.name !== "string" ||
        typeof file.mediaType !== "string" ||
        typeof file.plaintextBytes !== "number"
    ) {
        throw protocolError("Invalid shared-session encrypted file descriptor");
    }
    const result: EncryptedFileDescriptor = {
        version: 1,
        blobId: file.blobId,
        key: decodeBase64Url(file.key),
        nonce: decodeBase64Url(file.nonce),
        name: file.name,
        mediaType: file.mediaType,
        plaintextBytes: file.plaintextBytes,
    };
    validateFileDescriptor(result);
    return result;
}

function serializePageDescriptor(page: SharedSessionHistoryPageDescriptor): JsonValue {
    validateSequence(page.firstSequence);
    validateSequence(page.lastSequence);
    if (
        page.lastSequence < page.firstSequence ||
        !Number.isSafeInteger(page.entryCount) ||
        page.entryCount < 1 ||
        page.entryCount > MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES ||
        page.lastSequence - page.firstSequence + 1 !== page.entryCount ||
        page.file.plaintextBytes > MAX_SHARED_SESSION_HISTORY_PAGE_BYTES
    ) {
        throw new Error("Invalid shared-session history page descriptor");
    }
    return {
        entryCount: page.entryCount,
        file: sharedSessionFileToJson(page.file),
        firstSequence: page.firstSequence,
        lastSequence: page.lastSequence,
    };
}

function deserializePageDescriptor(value: unknown): SharedSessionHistoryPageDescriptor {
    const page = exactRecord(
        value,
        ["entryCount", "file", "firstSequence", "lastSequence"],
        "shared-session history page descriptor",
    );
    if (
        typeof page.entryCount !== "number" ||
        typeof page.firstSequence !== "number" ||
        typeof page.lastSequence !== "number"
    ) {
        throw protocolError("Invalid shared-session history page descriptor");
    }
    const result: SharedSessionHistoryPageDescriptor = {
        entryCount: page.entryCount,
        file: sharedSessionFileFromJson(page.file),
        firstSequence: page.firstSequence,
        lastSequence: page.lastSequence,
    };
    serializePageDescriptor(result);
    return result;
}

export function encodeSharedSessionHistoryPage(entries: readonly SharedSessionEntry[]): Uint8Array {
    if (entries.length === 0 || entries.length > MAX_SHARED_SESSION_HISTORY_PAGE_ENTRIES) {
        throw new Error("Invalid shared-session history page entry count");
    }
    for (let index = 1; index < entries.length; index += 1) {
        if (entries[index]!.shareSequence !== entries[index - 1]!.shareSequence + 1) {
            throw new Error("Shared-session history page is not gapless");
        }
    }
    const bytes = canonicalJsonBytes({
        entries: entries.map(sharedSessionEntryToJson),
        version: 1,
    });
    if (bytes.length > MAX_SHARED_SESSION_HISTORY_PAGE_BYTES) {
        throw new Error("Shared-session history page exceeds its plaintext bound");
    }
    return bytes;
}

export function decodeSharedSessionHistoryPage(bytes: Uint8Array): readonly SharedSessionEntry[] {
    if (bytes.length > MAX_SHARED_SESSION_HISTORY_PAGE_BYTES) {
        throw protocolError("Shared-session history page exceeds its plaintext bound");
    }
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    const value = exactRecord(parsed, ["entries", "version"], "shared-session history page");
    if (value.version !== 1 || !Array.isArray(value.entries)) {
        throw protocolError("Invalid shared-session history page");
    }
    const entries = value.entries.map(sharedSessionEntryFromJson);
    if (!equalBytes(encodeSharedSessionHistoryPage(entries), bytes)) {
        throw protocolError("Non-canonical shared-session history page");
    }
    return entries;
}

export function encodeSharedSessionHistoryOffer(offer: SharedSessionHistoryOffer): Uint8Array {
    validateSharedSessionShareId(offer.shareId);
    validateSequence(offer.throughSequence, true);
    if (
        !/^[A-Za-z0-9_-]{1,342}$/.test(offer.groupId) ||
        offer.pages.length > MAX_SHARED_SESSION_OFFER_PAGES
    ) {
        throw new Error("Invalid shared-session history offer");
    }
    return canonicalJsonBytes({
        groupId: offer.groupId,
        pages: offer.pages.map(serializePageDescriptor),
        ...(offer.previous === undefined
            ? {}
            : { previous: sharedSessionFileToJson(offer.previous) }),
        shareId: offer.shareId,
        throughSequence: offer.throughSequence,
        version: 1,
    });
}

export function decodeSharedSessionHistoryOffer(bytes: Uint8Array): SharedSessionHistoryOffer {
    const parsed = JSON.parse(utf8Decode(bytes)) as unknown;
    const value = optionalRecord(
        parsed,
        ["groupId", "pages", "shareId", "throughSequence", "version"],
        ["previous"],
        "shared-session history offer",
    );
    if (
        value.version !== 1 ||
        typeof value.groupId !== "string" ||
        !Array.isArray(value.pages) ||
        typeof value.shareId !== "string" ||
        typeof value.throughSequence !== "number"
    ) {
        throw protocolError("Invalid shared-session history offer");
    }
    const offer: SharedSessionHistoryOffer = {
        version: 1,
        groupId: value.groupId,
        pages: value.pages.map(deserializePageDescriptor),
        shareId: value.shareId,
        throughSequence: value.throughSequence,
        ...(value.previous === undefined
            ? {}
            : { previous: sharedSessionFileFromJson(value.previous) }),
    };
    if (!equalBytes(encodeSharedSessionHistoryOffer(offer), bytes)) {
        throw protocolError("Non-canonical shared-session history offer");
    }
    return offer;
}

function invitationUnsignedValue(
    invitation: Omit<DecodedSharedSessionInvitation, "signature">,
): JsonObject {
    return {
        commitFingerprint: encodeBase64Url(invitation.commitFingerprint),
        context: INVITATION_CONTEXT,
        grant: serializeGrant(invitation.grant),
        groupId: encodeBase64Url(invitation.groupId),
        ...(invitation.historyOffer === undefined
            ? {}
            : { historyOffer: sharedSessionFileToJson(invitation.historyOffer) }),
        keyPackageReference: encodeBase64Url(invitation.keyPackageReference),
        ownerId: invitation.ownerId,
        recipientId: invitation.recipientId,
        shareId: invitation.shareId,
        state: sharedSessionStateToJson(invitation.state),
        tree: encodeBase64Url(invitation.tree),
        version: 1,
        welcome: encodeBase64Url(invitation.welcome),
    };
}

export function encodeSharedSessionInvitation(
    invitation: Omit<DecodedSharedSessionInvitation, "signature">,
    owner: IdentityKeyPair,
): string {
    if (
        invitation.ownerId !== identityId(owner) ||
        invitation.grant.peerId !== invitation.recipientId ||
        invitation.state.ownerId !== invitation.ownerId ||
        invitation.state.shareId !== invitation.shareId ||
        invitation.state.groupId !== encodeBase64Url(invitation.groupId) ||
        invitation.keyPackageReference.length !== 32 ||
        invitation.commitFingerprint.length !== 32 ||
        invitation.welcome.length === 0 ||
        invitation.welcome.length > 1024 * 1024 ||
        invitation.tree.length === 0 ||
        invitation.tree.length > 16 * 1024 * 1024
    ) {
        throw new Error("Invalid shared-session invitation");
    }
    const unsigned = invitationUnsignedValue(invitation);
    return canonicalJson({
        ...unsigned,
        signature: encodeBase64Url(signBytes(owner, canonicalJsonBytes(unsigned))),
    });
}

export function decodeSharedSessionInvitation(
    text: string,
    expectedOwner: IdentityPublicKeys,
): DecodedSharedSessionInvitation {
    const parsed = JSON.parse(text) as unknown;
    const value = optionalRecord(
        parsed,
        [
            "commitFingerprint",
            "context",
            "grant",
            "groupId",
            "keyPackageReference",
            "ownerId",
            "recipientId",
            "shareId",
            "signature",
            "state",
            "tree",
            "version",
            "welcome",
        ],
        ["historyOffer"],
        "shared-session invitation",
    );
    if (
        value.version !== 1 ||
        value.context !== INVITATION_CONTEXT ||
        typeof value.commitFingerprint !== "string" ||
        typeof value.groupId !== "string" ||
        typeof value.keyPackageReference !== "string" ||
        typeof value.ownerId !== "string" ||
        typeof value.recipientId !== "string" ||
        typeof value.shareId !== "string" ||
        typeof value.signature !== "string" ||
        typeof value.tree !== "string" ||
        typeof value.welcome !== "string"
    ) {
        throw protocolError("Invalid shared-session invitation");
    }
    const signature = decodeBase64Url(value.signature);
    const unsignedObject = { ...value };
    delete unsignedObject.signature;
    if (
        value.ownerId !== identityId(expectedOwner) ||
        !isJsonValue(unsignedObject) ||
        !verifyBytes(expectedOwner, canonicalJsonBytes(unsignedObject), signature) ||
        canonicalJson(parsed as JsonValue) !== text
    ) {
        throw new SharedSessionProtocolError(
            "owner-authorization",
            "Invalid shared-session invitation owner signature",
        );
    }
    const result: DecodedSharedSessionInvitation = {
        version: 1,
        shareId: value.shareId,
        groupId: decodeBase64Url(value.groupId),
        ownerId: value.ownerId,
        recipientId: value.recipientId,
        state: sharedSessionStateFromJson(value.state),
        grant: deserializeGrant(value.grant),
        welcome: decodeBase64Url(value.welcome),
        tree: decodeBase64Url(value.tree),
        keyPackageReference: decodeBase64Url(value.keyPackageReference),
        commitFingerprint: decodeBase64Url(value.commitFingerprint),
        ...(value.historyOffer === undefined
            ? {}
            : { historyOffer: sharedSessionFileFromJson(value.historyOffer) }),
        signature,
    };
    if (
        result.state.ownerId !== result.ownerId ||
        result.state.shareId !== result.shareId ||
        result.state.groupId !== encodeBase64Url(result.groupId) ||
        result.grant.peerId !== result.recipientId
    ) {
        throw protocolError("Shared-session invitation binding mismatch");
    }
    invitationUnsignedValue(result);
    return result;
}
