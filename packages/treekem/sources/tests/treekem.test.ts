import { describe, expect, it } from "vitest";
import { apply, create, destroy, join, keyPair, update } from "../index.js";

function expectEqualBytes(left: Uint8Array, right: Uint8Array): void {
    expect(Array.from(left)).toEqual(Array.from(right));
}

describe("stateless TreeKEM API", () => {
    it("creates, adds, joins, and updates without mutating inputs", () => {
        const alice = keyPair();
        const bob = keyPair();
        const initial = create(alice);
        const initialSnapshot = initial.secretState.slice();

        const added = update(initial.secretState, { add: [bob.publicKey] });
        expectEqualBytes(initial.secretState, initialSnapshot);
        expect(added.publicWelcomes).toHaveLength(1);

        const joined = join(bob.secretKey, added.publicWelcomes[0]!);
        expectEqualBytes(added.secretKey, joined.secretKey);

        const joinedSnapshot = joined.secretState.slice();
        const bobUpdate = update(joined.secretState);
        expectEqualBytes(joined.secretState, joinedSnapshot);

        const aliceUpdate = apply(added.secretState, bobUpdate.publicPacket);
        expectEqualBytes(bobUpdate.secretKey, aliceUpdate.secretKey);

        destroy(
            alice.secretKey,
            bob.secretKey,
            initial.secretState,
            initial.secretKey,
            added.secretState,
            added.secretKey,
            joined.secretState,
            joined.secretKey,
            bobUpdate.secretState,
            bobUpdate.secretKey,
            aliceUpdate.secretState,
            aliceUpdate.secretKey,
        );
    });

    it("converges four branches and excludes a removed member", () => {
        const alice = keyPair();
        const bob = keyPair();
        const carol = keyPair();
        const dave = keyPair();
        const initial = create(alice);

        const group = update(initial.secretState, {
            add: [bob.publicKey, carol.publicKey, dave.publicKey],
        });
        const bobJoined = join(bob.secretKey, group.publicWelcomes[0]!);
        const carolJoined = join(carol.secretKey, group.publicWelcomes[1]!);
        const daveJoined = join(dave.secretKey, group.publicWelcomes[2]!);
        for (const member of [bobJoined, carolJoined, daveJoined]) {
            expectEqualBytes(member.secretKey, group.secretKey);
        }

        const carolUpdate = update(carolJoined.secretState);
        const aliceAfterCarol = apply(group.secretState, carolUpdate.publicPacket);
        const bobAfterCarol = apply(bobJoined.secretState, carolUpdate.publicPacket);
        const daveAfterCarol = apply(daveJoined.secretState, carolUpdate.publicPacket);
        for (const member of [aliceAfterCarol, bobAfterCarol, daveAfterCarol]) {
            expectEqualBytes(member.secretKey, carolUpdate.secretKey);
        }

        const removedBob = update(aliceAfterCarol.secretState, { remove: [bob.publicKey] });
        const carolAfterRemoval = apply(carolUpdate.secretState, removedBob.publicPacket);
        const daveAfterRemoval = apply(daveAfterCarol.secretState, removedBob.publicPacket);
        expectEqualBytes(carolAfterRemoval.secretKey, removedBob.secretKey);
        expectEqualBytes(daveAfterRemoval.secretKey, removedBob.secretKey);
        expect(() => apply(bobAfterCarol.secretState, removedBob.publicPacket)).toThrow(
            "Local member was removed",
        );

        const daveUpdate = update(daveAfterRemoval.secretState);
        const aliceAfterDave = apply(removedBob.secretState, daveUpdate.publicPacket);
        const carolAfterDave = apply(carolAfterRemoval.secretState, daveUpdate.publicPacket);
        expectEqualBytes(aliceAfterDave.secretKey, daveUpdate.secretKey);
        expectEqualBytes(carolAfterDave.secretKey, daveUpdate.secretKey);

        destroy(
            alice.secretKey,
            bob.secretKey,
            carol.secretKey,
            dave.secretKey,
            initial.secretState,
            initial.secretKey,
            group.secretState,
            group.secretKey,
            bobJoined.secretState,
            bobJoined.secretKey,
            carolJoined.secretState,
            carolJoined.secretKey,
            daveJoined.secretState,
            daveJoined.secretKey,
            carolUpdate.secretState,
            carolUpdate.secretKey,
            aliceAfterCarol.secretState,
            aliceAfterCarol.secretKey,
            bobAfterCarol.secretState,
            bobAfterCarol.secretKey,
            daveAfterCarol.secretState,
            daveAfterCarol.secretKey,
            removedBob.secretState,
            removedBob.secretKey,
            carolAfterRemoval.secretState,
            carolAfterRemoval.secretKey,
            daveAfterRemoval.secretState,
            daveAfterRemoval.secretKey,
            daveUpdate.secretState,
            daveUpdate.secretKey,
            aliceAfterDave.secretState,
            aliceAfterDave.secretKey,
            carolAfterDave.secretState,
            carolAfterDave.secretKey,
        );
    });

    it("rejects tampered, stale, and wrongly addressed public artifacts", () => {
        const alice = keyPair();
        const bob = keyPair();
        const mallory = keyPair();
        const initial = create(alice);
        const group = update(initial.secretState, { add: [bob.publicKey] });

        expect(() => join(mallory.secretKey, group.publicWelcomes[0]!)).toThrow();

        const bobJoined = join(bob.secretKey, group.publicWelcomes[0]!);
        const bobUpdate = update(bobJoined.secretState);
        const tamperedPacket = bobUpdate.publicPacket.slice();
        const packetLastIndex = tamperedPacket.length - 1;
        tamperedPacket[packetLastIndex] = (tamperedPacket[packetLastIndex] ?? 0) ^ 1;
        expect(() => apply(group.secretState, tamperedPacket)).toThrow(
            "Invalid TreeKEM update signature",
        );

        const aliceUpdated = apply(group.secretState, bobUpdate.publicPacket);
        expect(() => apply(aliceUpdated.secretState, bobUpdate.publicPacket)).toThrow(
            "does not extend the current state",
        );

        const tamperedWelcome = group.publicWelcomes[0]!.slice();
        const welcomeLastIndex = tamperedWelcome.length - 1;
        tamperedWelcome[welcomeLastIndex] = (tamperedWelcome[welcomeLastIndex] ?? 0) ^ 1;
        expect(() => join(bob.secretKey, tamperedWelcome)).toThrow(
            "Invalid TreeKEM Welcome signature",
        );

        destroy(
            alice.secretKey,
            bob.secretKey,
            mallory.secretKey,
            initial.secretState,
            initial.secretKey,
            group.secretState,
            group.secretKey,
            bobJoined.secretState,
            bobJoined.secretKey,
            bobUpdate.secretState,
            bobUpdate.secretKey,
            aliceUpdated.secretState,
            aliceUpdated.secretKey,
        );
    });

    it("atomically removes and adds multiple members", () => {
        const alice = keyPair();
        const bob = keyPair();
        const carol = keyPair();
        const dave = keyPair();
        const erin = keyPair();
        const frank = keyPair();
        const initial = create(alice);
        const group = update(initial.secretState, {
            add: [bob.publicKey, carol.publicKey, dave.publicKey],
        });
        const bobJoined = join(bob.secretKey, group.publicWelcomes[0]!);
        const carolJoined = join(carol.secretKey, group.publicWelcomes[1]!);
        const daveJoined = join(dave.secretKey, group.publicWelcomes[2]!);

        const changed = update(group.secretState, {
            remove: [bob.publicKey, carol.publicKey],
            add: [erin.publicKey, frank.publicKey],
        });
        expect(changed.publicWelcomes).toHaveLength(2);

        const daveChanged = apply(daveJoined.secretState, changed.publicPacket);
        const erinJoined = join(erin.secretKey, changed.publicWelcomes[0]!);
        const frankJoined = join(frank.secretKey, changed.publicWelcomes[1]!);
        for (const member of [daveChanged, erinJoined, frankJoined]) {
            expectEqualBytes(member.secretKey, changed.secretKey);
        }
        expect(() => apply(bobJoined.secretState, changed.publicPacket)).toThrow(
            "Local member was removed",
        );
        expect(() => apply(carolJoined.secretState, changed.publicPacket)).toThrow(
            "Local member was removed",
        );

        destroy(
            alice.secretKey,
            bob.secretKey,
            carol.secretKey,
            dave.secretKey,
            erin.secretKey,
            frank.secretKey,
            initial.secretState,
            initial.secretKey,
            group.secretState,
            group.secretKey,
            bobJoined.secretState,
            bobJoined.secretKey,
            carolJoined.secretState,
            carolJoined.secretKey,
            daveJoined.secretState,
            daveJoined.secretKey,
            changed.secretState,
            changed.secretKey,
            daveChanged.secretState,
            daveChanged.secretKey,
            erinJoined.secretState,
            erinJoined.secretKey,
            frankJoined.secretState,
            frankJoined.secretKey,
        );
    });

    it("rejects duplicate membership changes", () => {
        const alice = keyPair();
        const bob = keyPair();
        const initial = create(alice);

        expect(() => update(initial.secretState, { add: [bob.publicKey, bob.publicKey] })).toThrow(
            "repeats a member",
        );

        const group = update(initial.secretState, { add: [bob.publicKey] });
        expect(() => update(group.secretState, { add: [bob.publicKey] })).toThrow(
            "repeats a member",
        );
        expect(() => update(group.secretState, { remove: [bob.publicKey, bob.publicKey] })).toThrow(
            "repeats a member",
        );

        destroy(
            alice.secretKey,
            bob.secretKey,
            initial.secretState,
            initial.secretKey,
            group.secretState,
            group.secretKey,
        );
    });
});
