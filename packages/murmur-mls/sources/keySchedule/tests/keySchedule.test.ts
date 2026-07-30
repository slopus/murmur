import { randomBytes, utf8Encode } from "@slopus/murmur";
import { describe, expect, it } from "vitest";
import { deriveMlsEpochSecrets, deriveMlsInitialEpochSecrets } from "../index.js";

describe("RFC 9420 epoch key schedule", () => {
    it("derives independent 32-byte epoch secrets", () => {
        const secrets = deriveMlsEpochSecrets(
            randomBytes(32),
            randomBytes(32),
            utf8Encode("group context"),
        );

        expect(secrets.encryptionSecret).toHaveLength(32);
        expect(secrets.encryptionSecret).not.toEqual(secrets.exporterSecret);
        expect(secrets.nextInitSecret).not.toEqual(secrets.epochSecret);
    });

    it("binds the member secret to the group context", () => {
        const init = randomBytes(32);
        const commit = randomBytes(32);

        expect(deriveMlsEpochSecrets(init, commit, utf8Encode("epoch 1")).memberSecret).not.toEqual(
            deriveMlsEpochSecrets(init, commit, utf8Encode("epoch 2")).memberSecret,
        );
    });

    it("derives epoch zero directly from fresh creator entropy", () => {
        const epochSecret = randomBytes(32);
        const expected = epochSecret.slice();
        const secrets = deriveMlsInitialEpochSecrets(epochSecret);

        expect(epochSecret).toEqual(expected);
        expect(secrets.epochSecret).toEqual(expected);
        expect(secrets.joinerSecret).toEqual(new Uint8Array(32));
        expect(secrets.memberSecret).toEqual(new Uint8Array(32));
        expect(secrets.confirmationKey).not.toEqual(secrets.encryptionSecret);
    });
});
