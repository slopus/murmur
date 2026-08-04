import type { IdentityKeyPair } from "../../crypto/index.js";
import { hashBytes } from "../../crypto/index.js";
import { createMlsKeyPackage, type MlsEpochState } from "../../mls/index.js";
import { concatBytes, decodeBase64Url, utf8Encode, zeroBytes } from "../../utils/index.js";
import type { MurmurGroup } from "../types.js";
import type {
    GroupOperation,
    RelayOutboxRecord,
    StagedGroupCommit,
    StoredGroup,
} from "./stateCodec.js";

const MLS_PROTOCOL_VERSION = 1;
const MLS_PUBLIC_MESSAGE = 1;

/** In-memory group checkpoint restored from clean durable state. */
export interface RuntimeGroup {
    record: StoredGroup;
    epoch?: MlsEpochState;
}

/** Bind opaque descriptor bytes to one random group identifier and nonce. */
export function descriptorBinding(
    groupId: Uint8Array,
    nonce: Uint8Array,
    descriptor: Uint8Array,
): Uint8Array {
    return hashBytes(
        concatBytes(utf8Encode("murmur/group-descriptor/v1"), groupId, nonce, descriptor),
    );
}

/** Create one bounded-pool KeyPackage with a non-expiring clean-rewrite lifetime. */
export function createMurmurKeyPackage(
    identity: IdentityKeyPair,
): ReturnType<typeof createMlsKeyPackage> {
    const nowSeconds = Math.floor(Date.now() / 1_000);
    return createMlsKeyPackage(identity, nowSeconds, Number.MAX_SAFE_INTEGER - nowSeconds);
}

/** Identify the RFC wire content type used by public Commit messages. */
export function isCommit(payload: Uint8Array): boolean {
    return (
        payload.length >= 4 &&
        (((payload[0] ?? 0) << 8) | (payload[1] ?? 0)) === MLS_PROTOCOL_VERSION &&
        (((payload[2] ?? 0) << 8) | (payload[3] ?? 0)) === MLS_PUBLIC_MESSAGE
    );
}

/** Convert durable group state to its defensive facade view. */
export function groupView(group: RuntimeGroup): MurmurGroup {
    return {
        id: decodeBase64Url(group.record.id),
        descriptor: group.record.descriptor.slice(),
        members: group.record.members.map((member) => member.slice()),
        epoch: group.record.epoch,
        status: group.record.status,
    };
}

/** Zero secret-bearing staged Commit copies after use. */
export function destroyStagedCommit(staged: StagedGroupCommit | undefined): void {
    if (staged === undefined) {
        return;
    }
    zeroBytes(staged.nextEpoch);
    zeroBytes(staged.fingerprint);
    zeroBytes(staged.peer);
    staged.keyPackageReference?.fill(0);
    staged.welcome?.fill(0);
    staged.tree?.fill(0);
}

/** Zero decoded retained plaintext operations and their attempt fingerprints. */
export function destroyGroupOperation(operation: GroupOperation): void {
    if (operation.type === "send") {
        zeroBytes(operation.payload);
        operation.attempt?.fingerprint.fill(0);
        return;
    }
    zeroBytes(operation.peer);
}

/** Zero byte arrays owned by one decoded durable group record. */
export function destroyStoredGroup(group: StoredGroup | undefined): void {
    if (group === undefined) {
        return;
    }
    zeroBytes(group.descriptor);
    zeroBytes(group.descriptorNonce);
    zeroBytes(group.descriptorBinding);
    zeroBytes(group.topicSecret);
    for (const member of group.members) {
        zeroBytes(member);
    }
}

/** Zero decoded exact relay-event copies after reconciliation scans. */
export function destroyRelayOutboxRecord(record: RelayOutboxRecord | undefined): void {
    if (record === undefined) {
        return;
    }
    zeroBytes(record.event.author.signingKey);
    zeroBytes(record.event.payload);
    zeroBytes(record.event.signature);
    record.event.collapseKey?.fill(0);
    if (record.event.topic.type === "write") {
        zeroBytes(record.event.topic.writeKey);
    } else if (record.event.topic.type === "read") {
        zeroBytes(record.event.topic.readKey);
    } else {
        zeroBytes(record.event.topic.readKey);
        zeroBytes(record.event.topic.writeKey);
    }
}
