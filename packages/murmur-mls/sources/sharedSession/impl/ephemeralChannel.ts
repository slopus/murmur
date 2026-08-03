import { equalBytes, identityId, utf8Encode, zeroBytes } from "@slopus/murmur";
import {
    MLS_EPHEMERAL_CHANNEL_SECRET_BYTES,
    MLS_EPHEMERAL_EXPORTER_LABEL,
    MlsEphemeralCipher,
    type MlsEphemeralDropReason,
} from "../../ephemeral/index.js";
import type { MlsGroupChannel } from "../../groupChannel/index.js";
import type {
    SharedSessionEphemeralChannel,
    SharedSessionEphemeralDrop,
    SharedSessionEphemeralEpochChange,
    SharedSessionEphemeralFrame,
    SharedSessionEphemeralOptions,
    SharedSessionEphemeralTransport,
    SharedSessionMemberGrant,
    SharedSessionTopicStream,
} from "../types.js";
import {
    MAX_SHARED_SESSION_EPHEMERAL_BYTES,
    MAX_SHARED_SESSION_EPHEMERAL_QUEUE_BYTES,
    MAX_SHARED_SESSION_EPHEMERAL_QUEUE_FRAMES,
    SHARED_SESSION_OWNER_MEMBER_ID,
} from "../types.js";

/** Live view of the owner-authoritative facts an ephemeral frame is judged by. */
export interface SharedSessionEphemeralContext {
    readonly shareId: string;
    readonly role: "owner" | "member";
    readonly localId: string;
    readonly ownerSigningKey: Uint8Array;
    readonly members: readonly SharedSessionMemberGrant[];
}

interface QueuedFrame {
    readonly bytes: Uint8Array;
    readonly epoch: bigint;
}

function safeEpoch(epoch: bigint): number {
    if (epoch > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("MLS epoch exceeds the safe integer range");
    }
    return Number(epoch);
}

function inboundReason(
    reason: Exclude<MlsEphemeralDropReason, "self">,
): SharedSessionEphemeralDrop["reason"] {
    return reason;
}

/**
 * Ephemeral channel bound to one shared-session MLS group.
 *
 * ```text
 * send(bytes) ─► bounded queue ─► seal under current epoch ─► POST ephemeral
 *                    │
 *                    └─ oldest frames dropped, never buffered without bound
 *
 * relay stream ─► open under current epoch ─► grant check ─► onReceived
 *                    │
 *                    └─ foreign epoch ─► onEpochChanged (peer ahead/behind)
 * ```
 */
export class SharedSessionEphemeralChannelImpl implements SharedSessionEphemeralChannel {
    readonly #transport: SharedSessionEphemeralTransport;
    readonly #topic: string;
    readonly #context: () => SharedSessionEphemeralContext;
    readonly #identity: import("@slopus/murmur").IdentityKeyPair;
    readonly #maximumQueuedFrames: number;
    readonly #maximumQueuedBytes: number;
    readonly #onWake: (() => void) | undefined;
    readonly #received = new Set<(frame: SharedSessionEphemeralFrame) => void>();
    readonly #dropped = new Set<(drop: SharedSessionEphemeralDrop) => void>();
    readonly #epochChanged = new Set<(change: SharedSessionEphemeralEpochChange) => void>();
    readonly #queue: QueuedFrame[] = [];
    #queuedBytes = 0;
    #cipher: MlsEphemeralCipher;
    #groupChannel: MlsGroupChannel;
    #stream: SharedSessionTopicStream | undefined;
    #pumping = false;
    #open = true;

    constructor(options: {
        readonly transport: SharedSessionEphemeralTransport;
        readonly groupChannel: MlsGroupChannel;
        readonly identity: import("@slopus/murmur").IdentityKeyPair;
        readonly context: () => SharedSessionEphemeralContext;
        readonly options: SharedSessionEphemeralOptions;
    }) {
        const bounds = options.options;
        const maximumQueuedFrames =
            bounds.maximumQueuedFrames ?? MAX_SHARED_SESSION_EPHEMERAL_QUEUE_FRAMES;
        const maximumQueuedBytes =
            bounds.maximumQueuedBytes ?? MAX_SHARED_SESSION_EPHEMERAL_QUEUE_BYTES;
        if (
            !Number.isSafeInteger(maximumQueuedFrames) ||
            maximumQueuedFrames < 1 ||
            maximumQueuedFrames > MAX_SHARED_SESSION_EPHEMERAL_QUEUE_FRAMES ||
            !Number.isSafeInteger(maximumQueuedBytes) ||
            maximumQueuedBytes < MAX_SHARED_SESSION_EPHEMERAL_BYTES ||
            maximumQueuedBytes > MAX_SHARED_SESSION_EPHEMERAL_QUEUE_BYTES
        ) {
            throw new Error("Invalid shared-session ephemeral channel bounds");
        }
        this.#transport = options.transport;
        this.#groupChannel = options.groupChannel;
        this.#identity = options.identity;
        this.#context = options.context;
        this.#topic = options.groupChannel.topic;
        this.#maximumQueuedFrames = maximumQueuedFrames;
        this.#maximumQueuedBytes = maximumQueuedBytes;
        this.#onWake = bounds.onWake;
        this.#cipher = this.#createCipher(options.groupChannel);
        this.#stream = this.#transport.openTopicStream(this.#topic, {
            onFrame: (frame) => {
                this.#receive(frame.bytes);
            },
            onWake: () => {
                this.#onWake?.();
            },
            onDrop: (drop) => {
                this.#report({
                    direction: "inbound",
                    reason: "relay",
                    frames: drop.frames,
                });
            },
        });
    }

    get epoch(): number {
        return safeEpoch(this.#cipher.epoch);
    }

    get open(): boolean {
        return this.#open;
    }

    readonly onReceived = (handler: (frame: SharedSessionEphemeralFrame) => void): (() => void) => {
        this.#received.add(handler);
        return () => {
            this.#received.delete(handler);
        };
    };

    readonly onDropped = (handler: (drop: SharedSessionEphemeralDrop) => void): (() => void) => {
        this.#dropped.add(handler);
        return () => {
            this.#dropped.delete(handler);
        };
    };

    readonly onEpochChanged = (
        handler: (change: SharedSessionEphemeralEpochChange) => void,
    ): (() => void) => {
        this.#epochChanged.add(handler);
        return () => {
            this.#epochChanged.delete(handler);
        };
    };

    send(bytes: Uint8Array): void {
        if (!this.#open) {
            throw new Error("Shared-session ephemeral channel is closed");
        }
        if (bytes.length > MAX_SHARED_SESSION_EPHEMERAL_BYTES) {
            throw new Error(
                `Ephemeral frame exceeds ${MAX_SHARED_SESSION_EPHEMERAL_BYTES.toString()} bytes`,
            );
        }
        const context = this.#context();
        if (context.role === "member" && this.#localGrant(context) === undefined) {
            throw new Error("Local identity has no active shared-session grant");
        }
        const frame: QueuedFrame = {
            bytes: this.#cipher.seal(bytes),
            epoch: this.#cipher.epoch,
        };
        this.#queue.push(frame);
        this.#queuedBytes += frame.bytes.length;
        let overflow = 0;
        while (
            this.#queue.length > this.#maximumQueuedFrames ||
            (this.#queuedBytes > this.#maximumQueuedBytes && this.#queue.length > 1)
        ) {
            const evicted = this.#queue.shift();
            if (evicted === undefined) {
                break;
            }
            this.#queuedBytes -= evicted.bytes.length;
            zeroBytes(evicted.bytes);
            overflow += 1;
        }
        if (overflow > 0) {
            this.#report({ direction: "outbound", reason: "queue-overflow", frames: overflow });
        }
        void this.#pump();
    }

    /**
     * Adopt a new epoch after the session applied a Commit.
     *
     * Queued frames sealed under the previous epoch are void: no member can
     * open them any more, so they are dropped rather than published.
     */
    rekey(groupChannel: MlsGroupChannel): void {
        if (!this.#open) {
            return;
        }
        const previousEpoch = this.#cipher.epoch;
        if (groupChannel.epoch === previousEpoch && groupChannel === this.#groupChannel) {
            return;
        }
        const next = this.#createCipher(groupChannel);
        this.#cipher.destroy();
        this.#cipher = next;
        this.#groupChannel = groupChannel;
        const discarded = this.#drainQueue();
        if (discarded > 0) {
            this.#report({ direction: "outbound", reason: "epoch-change", frames: discarded });
        }
        this.#announce({
            reason: "local-commit",
            localEpoch: safeEpoch(groupChannel.epoch),
            observedEpoch: safeEpoch(previousEpoch),
        });
    }

    close(): void {
        if (!this.#open) {
            return;
        }
        this.#open = false;
        this.#stream?.close();
        this.#stream = undefined;
        const discarded = this.#drainQueue();
        if (discarded > 0) {
            this.#report({ direction: "outbound", reason: "closed", frames: discarded });
        }
        this.#cipher.destroy();
        this.#received.clear();
        this.#dropped.clear();
        this.#epochChanged.clear();
    }

    #createCipher(groupChannel: MlsGroupChannel): MlsEphemeralCipher {
        const context = this.#context();
        const channelSecret = groupChannel.exportSecret(
            MLS_EPHEMERAL_EXPORTER_LABEL,
            utf8Encode(context.shareId),
            MLS_EPHEMERAL_CHANNEL_SECRET_BYTES,
        );
        try {
            return new MlsEphemeralCipher({
                groupId: groupChannel.groupId,
                epoch: groupChannel.epoch,
                localLeaf: groupChannel.localLeaf,
                identity: this.#identity,
                channelSecret,
                signatureKeyFor: (leaf) => groupChannel.memberSignatureKeys[leaf],
            });
        } finally {
            zeroBytes(channelSecret);
        }
    }

    #drainQueue(): number {
        const discarded = this.#queue.length;
        for (const queued of this.#queue.splice(0)) {
            zeroBytes(queued.bytes);
        }
        this.#queuedBytes = 0;
        return discarded;
    }

    async #pump(): Promise<void> {
        if (this.#pumping) {
            return;
        }
        this.#pumping = true;
        try {
            for (;;) {
                const next = this.#queue.shift();
                if (next === undefined) {
                    return;
                }
                this.#queuedBytes -= next.bytes.length;
                if (!this.#open || next.epoch !== this.#cipher.epoch) {
                    zeroBytes(next.bytes);
                    this.#report({
                        direction: "outbound",
                        reason: this.#open ? "epoch-change" : "closed",
                        frames: 1,
                    });
                    continue;
                }
                try {
                    await this.#transport.publishEphemeral(this.#topic, next.bytes);
                } catch {
                    this.#report({ direction: "outbound", reason: "relay", frames: 1 });
                } finally {
                    zeroBytes(next.bytes);
                }
            }
        } finally {
            this.#pumping = false;
        }
    }

    #receive(bytes: Uint8Array): void {
        if (!this.#open) {
            return;
        }
        const opened = this.#cipher.open(bytes);
        if (opened.status === "dropped") {
            if (opened.reason === "self") {
                return;
            }
            if (opened.reason === "foreign-epoch" && opened.epoch !== undefined) {
                const localEpoch = safeEpoch(this.#cipher.epoch);
                const observedEpoch = safeEpoch(opened.epoch);
                this.#announce({
                    reason: observedEpoch > localEpoch ? "peer-ahead" : "peer-behind",
                    localEpoch,
                    observedEpoch,
                });
            }
            this.#report({
                direction: "inbound",
                reason: inboundReason(opened.reason),
                frames: 1,
            });
            return;
        }
        const frame = opened.frame;
        try {
            if (frame.type !== "data") {
                return;
            }
            const context = this.#context();
            const senderKey = this.#groupChannel.memberSignatureKeys[frame.senderLeaf];
            if (senderKey === undefined) {
                this.#report({ direction: "inbound", reason: "unknown-sender", frames: 1 });
                return;
            }
            const ownerAuthored = equalBytes(senderKey, context.ownerSigningKey);
            const peerId = identityId({ signingKey: senderKey });
            if (ownerAuthored) {
                // The owner drives the transcript; a member only accepts the
                // owner, exactly as it does on the durable channel.
                if (context.role !== "member") {
                    this.#report({ direction: "inbound", reason: "not-granted", frames: 1 });
                    return;
                }
                this.#deliver({
                    authenticatedPeerId: peerId,
                    shareMemberId: SHARED_SESSION_OWNER_MEMBER_ID,
                    grantEpoch: 0,
                    bytes: frame.bytes,
                });
                return;
            }
            const grant = context.members.find(
                (member) => member.peerId === peerId && member.status === "active",
            );
            if (context.role !== "owner" || grant === undefined) {
                this.#report({ direction: "inbound", reason: "not-granted", frames: 1 });
                return;
            }
            this.#deliver({
                authenticatedPeerId: peerId,
                shareMemberId: grant.shareMemberId,
                grantEpoch: grant.grantEpoch,
                bytes: frame.bytes,
            });
        } finally {
            zeroBytes(frame.bytes);
        }
    }

    #deliver(frame: SharedSessionEphemeralFrame): void {
        // Snapshot first: a handler is allowed to unsubscribe while notified.
        const handlers = [...this.#received];
        for (const handler of handlers) {
            handler({ ...frame, bytes: frame.bytes.slice() });
        }
    }

    #report(drop: SharedSessionEphemeralDrop): void {
        const handlers = [...this.#dropped];
        for (const handler of handlers) {
            handler(drop);
        }
    }

    #announce(change: SharedSessionEphemeralEpochChange): void {
        const handlers = [...this.#epochChanged];
        for (const handler of handlers) {
            handler(change);
        }
    }

    #localGrant(context: SharedSessionEphemeralContext): SharedSessionMemberGrant | undefined {
        return context.members.find(
            (member) => member.peerId === context.localId && member.status === "active",
        );
    }
}
