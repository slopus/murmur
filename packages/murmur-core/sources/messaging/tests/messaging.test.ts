import { describe, expect, it } from "vitest";
import { utf8Decode, utf8Encode } from "../../utils/index.js";
import {
    createPrivateMessage,
    decodePrivateMessage,
    decryptFile,
    encodePrivateMessage,
    encryptFile,
} from "../index.js";

describe("encrypted files", () => {
    it("encrypts relay blobs and authenticates their metadata", () => {
        const encrypted = encryptFile(utf8Encode("private"), {
            name: "note.txt",
            mediaType: "text/plain",
        });

        expect(encrypted.blob.bytes).not.toEqual(utf8Encode("private"));
        expect(utf8Decode(decryptFile(encrypted.descriptor, encrypted.blob))).toBe("private");
        expect(() =>
            decryptFile({ ...encrypted.descriptor, name: "changed.txt" }, encrypted.blob),
        ).toThrow();
    });

    it("rejects path-like file names", () => {
        expect(() => encryptFile(utf8Encode("private"), { name: "../secret" })).toThrow(
            "descriptor",
        );
        for (const name of [
            "file:stream",
            "C:secret",
            "CON",
            "CONIN$",
            "COM¹",
            "report.",
            "😀".repeat(64),
        ]) {
            expect(() => encryptFile(utf8Encode("private"), { name })).toThrow("descriptor");
        }
    });
});

describe("private message content", () => {
    it("round trips an encrypted file descriptor", () => {
        const file = encryptFile(utf8Encode("private"), { name: "note.txt" });
        const message = createPrivateMessage("hello", [file.descriptor], 42);

        expect(decodePrivateMessage(encodePrivateMessage(message))).toEqual(message);
    });

    it("rejects more than 64 attachments", () => {
        const file = encryptFile(new Uint8Array(), { name: "empty" });

        expect(() =>
            createPrivateMessage(
                "",
                Array.from({ length: 65 }, () => file.descriptor),
            ),
        ).toThrow("message");
    });

    it("rejects unknown attachment versions instead of coercing them to version 1", () => {
        const file = encryptFile(utf8Encode("private"), { name: "note.txt" });
        const encoded = utf8Decode(
            encodePrivateMessage(createPrivateMessage("hello", [file.descriptor], 42)),
        ).replace('"version":1,"blobId"', '"version":2,"blobId"');

        expect(() => decodePrivateMessage(utf8Encode(encoded))).toThrow("descriptor");
    });

    it("rejects attachment plaintext sizes above the supported file limit", () => {
        const file = encryptFile(utf8Encode("private"), { name: "note.txt" });
        const encoded = utf8Decode(
            encodePrivateMessage(createPrivateMessage("hello", [file.descriptor], 42)),
        ).replace('"plaintextBytes":7', `"plaintextBytes":${Number.MAX_SAFE_INTEGER}`);

        expect(() => decodePrivateMessage(utf8Encode(encoded))).toThrow("descriptor");
    });
});
