import type { IdentityKeyPair, IdentityPublicKey } from "../../crypto/index.js";
import { identityId } from "../../identity/index.js";
import type { MurmurStore, StoreScanOptions, StoreTransaction } from "../../storage/index.js";
import { encodeBase64Url, utf8Decode, utf8Encode } from "../../utils/index.js";

export const ROOT_KEY = "murmur/v1/root";
export const PROFILE_KEY = "murmur/v1/profile";
export const OUTBOX_PREFIX = "murmur/v1/relay-outbox/";
export const CURSOR_PREFIX = "murmur/v1/cursors/";
const GROUPS_PREFIX = "murmur/v1/groups/";
export const GROUP_INDEX_PREFIX = "murmur/v1/group-index/";
export const LOCAL_KEY_PACKAGE_PREFIX = "murmur/v1/key-packages/local/";
export const LOCAL_KEY_PACKAGE_CONSUMED_PREFIX = "murmur/v1/key-packages/local-consumed/";
export const REMOTE_KEY_PACKAGE_PREFIX = "murmur/v1/key-packages/remote/";
export const REMOTE_KEY_PACKAGE_CONSUMED_PREFIX = "murmur/v1/key-packages/remote-consumed/";
export const KEY_PACKAGE_REQUEST_PREFIX = "murmur/v1/key-packages/requests/";
export const KEY_PACKAGE_NEEDED_PREFIX = "murmur/v1/key-packages/needed/";
export const CONTROL_REPLAY_PREFIX = "murmur/v1/control-replay/";
export const CONTROL_SELF_PREFIX = "murmur/v1/control-self/";
export const QUARANTINE_PREFIX = "murmur/v1/quarantine/";
export const DEFERRED_INVITATION_PREFIX = "murmur/v1/deferred-invitations/";

/** Adapt an existing transaction without opening a nested transaction. */
export class TransactionStore implements MurmurStore {
    readonly #transaction: StoreTransaction;

    constructor(transaction: StoreTransaction) {
        this.#transaction = transaction;
    }

    get(key: string): Promise<Uint8Array | undefined> {
        return this.#transaction.get(key);
    }

    set(key: string, value: Uint8Array): Promise<void> {
        return this.#transaction.set(key, value);
    }

    delete(key: string): Promise<void> {
        return this.#transaction.delete(key);
    }

    list(prefix: string): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#transaction.list(prefix);
    }

    scan(prefix: string, options: StoreScanOptions): Promise<ReadonlyMap<string, Uint8Array>> {
        return this.#transaction.scan(prefix, options);
    }

    transaction<Result>(
        operation: (transaction: StoreTransaction) => Promise<Result>,
    ): Promise<Result> {
        return operation(this.#transaction);
    }
}

/** Encode one relay cursor for durable storage. */
export function cursorBytes(cursor: bigint): Uint8Array {
    return utf8Encode(cursor.toString());
}

/** Strictly decode one durable relay cursor. */
export function parseCursor(value: Uint8Array | undefined): bigint {
    if (value === undefined) {
        return 0n;
    }
    const text = utf8Decode(value);
    if (!/^(0|[1-9]\d*)$/.test(text)) {
        throw new Error("Invalid Murmur cursor");
    }
    const cursor = BigInt(text);
    if (cursor > 0x7fff_ffff_ffff_ffffn) {
        throw new Error("Murmur cursor exceeds relay sequence range");
    }
    return cursor;
}

/** Fixed-width lexicographic representation of a relay sequence. */
export function sequenceKey(sequence: bigint): string {
    return sequence.toString().padStart(20, "0");
}

function groupBase(groupId: string): string {
    return `${GROUPS_PREFIX}${groupId}/`;
}

/** Durable metadata key for one group. */
export function groupMetaKey(groupId: string): string {
    return `${groupBase(groupId)}meta`;
}

/** Separate group discovery index key. */
export function groupIndexKey(groupId: string): string {
    return `${GROUP_INDEX_PREFIX}${groupId}`;
}

/** Durable active epoch key for one group. */
export function groupEpochKey(groupId: string): string {
    return `${groupBase(groupId)}epoch`;
}

/** Durable staged next-epoch key for one group. */
export function groupStagedKey(groupId: string): string {
    return `${groupBase(groupId)}staged`;
}

/** Prefix for retained high-level group operations. */
export function groupOperationPrefix(groupId: string): string {
    return `${groupBase(groupId)}operations/`;
}

/** Durable high-level group operation key. */
export function groupOperationKey(groupId: string, operationId: string): string {
    return `${groupOperationPrefix(groupId)}${operationId}`;
}

/** Prefix for retained opaque group application events. */
export function groupEventPrefix(groupId: string): string {
    return `${groupBase(groupId)}events/`;
}

/** Durable ordered opaque group event key. */
export function groupEventKey(groupId: string, sequence: bigint): string {
    return `${groupEventPrefix(groupId)}${sequenceKey(sequence)}`;
}

/** Replay marker key for one authenticated group payload. */
export function groupReplayKey(groupId: string, fingerprint: Uint8Array): string {
    return `${groupBase(groupId)}replay/${encodeBase64Url(fingerprint)}`;
}

/** Durable sequence-order index used to bound authenticated replay markers. */
export function groupReplayOrderKey(groupId: string, sequence: bigint): string {
    return `${groupBase(groupId)}replay-order/${sequenceKey(sequence)}`;
}

function friendBookPrefix(owner: IdentityKeyPair): string {
    return `murmur/v1/friend-book/${identityId(owner)}/`;
}

/** Durable friend record key within the identity-owned book. */
export function friendRecordKey(owner: IdentityKeyPair, peer: IdentityPublicKey): string {
    return `${friendBookPrefix(owner)}records/${identityId(peer)}`;
}

/** Semantic friend outbox key within the identity-owned book. */
export function friendOutboxKey(owner: IdentityKeyPair, id: string): string {
    return `${friendBookPrefix(owner)}outbox/${id}`;
}

/** Durable local private KeyPackage bundle key. */
export function localKeyPackageKey(peer: IdentityPublicKey, reference: Uint8Array): string {
    return `${LOCAL_KEY_PACKAGE_PREFIX}${identityId(peer)}/${encodeBase64Url(reference)}`;
}

/** Durable remote public KeyPackage key. */
export function remoteKeyPackageKey(peer: IdentityPublicKey, reference: Uint8Array): string {
    return `${REMOTE_KEY_PACKAGE_PREFIX}${identityId(peer)}/${encodeBase64Url(reference)}`;
}
