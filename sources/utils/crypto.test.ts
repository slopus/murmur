import { describe, it, expect } from 'vitest';
import { generateKeyPair, signMessage, verifySignature, isValidPublicKey } from './crypto';

describe('crypto utilities', () => {
    describe('generateKeyPair', () => {
        it('should generate a valid key pair', () => {
            const keyPair = generateKeyPair();
            expect(keyPair.publicKey).toBeDefined();
            expect(keyPair.privateKey).toBeDefined();
            expect(typeof keyPair.publicKey).toBe('string');
            expect(typeof keyPair.privateKey).toBe('string');
        });

        it('should generate different key pairs each time', () => {
            const keyPair1 = generateKeyPair();
            const keyPair2 = generateKeyPair();
            expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
            expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
        });
    });

    describe('signMessage and verifySignature', () => {
        it('should sign and verify a message', () => {
            const keyPair = generateKeyPair();
            const message = 'Hello, World!';
            const signature = signMessage(message, keyPair.privateKey);

            expect(verifySignature(message, signature, keyPair.publicKey)).toBe(true);
        });

        it('should reject invalid signature', () => {
            const keyPair = generateKeyPair();
            const message = 'Hello, World!';
            const signature = signMessage(message, keyPair.privateKey);

            // Tamper with the message
            const tamperedMessage = 'Hello, World?';
            expect(verifySignature(tamperedMessage, signature, keyPair.publicKey)).toBe(false);
        });

        it('should reject signature from different key', () => {
            const keyPair1 = generateKeyPair();
            const keyPair2 = generateKeyPair();
            const message = 'Hello, World!';
            const signature = signMessage(message, keyPair1.privateKey);

            expect(verifySignature(message, signature, keyPair2.publicKey)).toBe(false);
        });

        it('should handle Uint8Array messages', () => {
            const keyPair = generateKeyPair();
            const message = new Uint8Array([1, 2, 3, 4, 5]);
            const signature = signMessage(message, keyPair.privateKey);

            expect(verifySignature(message, signature, keyPair.publicKey)).toBe(true);
        });
    });

    describe('isValidPublicKey', () => {
        it('should validate a valid public key', () => {
            const keyPair = generateKeyPair();
            expect(isValidPublicKey(keyPair.publicKey)).toBe(true);
        });

        it('should reject invalid base64', () => {
            expect(isValidPublicKey('not-valid-base64!!!')).toBe(false);
        });

        it('should reject wrong length key', () => {
            expect(isValidPublicKey('YWJjZGVm')).toBe(false); // Too short
        });

        it('should reject empty string', () => {
            expect(isValidPublicKey('')).toBe(false);
        });
    });
});
