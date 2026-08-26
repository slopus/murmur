import { describe, expect, test } from "vitest";
import { canonicalJsonBytes, encodeBase64Url, utf8Encode } from "../../../utils/index.js";
import { parseSessionCiphertext, sealCommitCiphertext } from "../sessionFrames.js";

const MAXIMUM_UINT64 = 2n ** 64n - 1n;

function commitCiphertext(epoch: string): Uint8Array {
    return new Uint8Array([
        3,
        ...canonicalJsonBytes({
            version: 1,
            groupId: encodeBase64Url(utf8Encode("group")),
            epoch,
            nonce: encodeBase64Url(new Uint8Array(12)),
            ciphertext: encodeBase64Url(new Uint8Array(16)),
        }),
    ]);
}

describe("session frame codecs", () => {
    test("accepts only canonical uint64 Commit epochs", () => {
        expect(parseSessionCiphertext(commitCiphertext("0"))).toMatchObject({
            kind: "commit",
            epoch: 0n,
        });
        expect(parseSessionCiphertext(commitCiphertext(MAXIMUM_UINT64.toString()))).toMatchObject({
            kind: "commit",
            epoch: MAXIMUM_UINT64,
        });
        for (const epoch of [
            "",
            "00",
            "01",
            "+1",
            "-0",
            "1.0",
            " 1",
            (2n ** 64n).toString(),
            (2n ** 64n + 1n).toString(),
            (2n ** 128n).toString(),
        ]) {
            expect(() => parseSessionCiphertext(commitCiphertext(epoch)), epoch).toThrow(
                "Invalid Commit ciphertext",
            );
        }
    });

    test("does not seal an out-of-range Commit epoch", () => {
        const roles = {
            owner: new Uint8Array(32).fill(1),
            admins: [],
            adminsAssignAdmins: false,
            anyoneCanAddMembers: false,
        };
        for (const epoch of [-1n, 2n ** 64n]) {
            expect(() =>
                sealCommitCiphertext(new Uint8Array(32), {
                    version: 1,
                    groupId: utf8Encode("group"),
                    epoch,
                    commit: utf8Encode("commit"),
                    roles,
                }),
            ).toThrow("Invalid Commit frame");
        }
    });
});
