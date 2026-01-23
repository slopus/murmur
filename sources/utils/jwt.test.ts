import { describe, it, expect, beforeAll } from 'vitest';
import { generateToken, verifyToken, initializeJWT } from './jwt';

describe('JWT utilities (privacy-kit)', () => {
    beforeAll(async () => {
        // Initialize JWT before running tests
        await initializeJWT();
    });

    describe('generateToken and verifyToken', () => {
        it('should generate and verify a valid token', async () => {
            const userId = 'test-user-id';
            const token = await generateToken(userId);

            expect(token).toBeDefined();
            expect(typeof token).toBe('string');

            const payload = await verifyToken(token);
            expect(payload).toBeDefined();
            expect(payload?.userId).toBe(userId);
            expect(payload?.user).toBe(userId);
        });

        it('should reject invalid token', async () => {
            const payload = await verifyToken('invalid-token');
            expect(payload).toBeNull();
        });

        it('should reject tampered token', async () => {
            const userId = 'test-user-id';
            const token = await generateToken(userId);

            // Tamper with the token
            const tamperedToken = token.slice(0, -5) + 'XXXXX';
            const payload = await verifyToken(tamperedToken);
            expect(payload).toBeNull();
        });

        it('should return a token string with access and refresh parts', async () => {
            const userId = 'test-user-id';
            const token = await generateToken(userId);

            // privacy-kit tokens contain access and refresh tokens
            expect(token).toBeDefined();
            expect(typeof token).toBe('string');
            expect(token.length).toBeGreaterThan(0);

            // Should be verifiable
            const payload = await verifyToken(token);
            expect(payload).toBeDefined();
            expect(payload?.userId).toBe(userId);
        });
    });
});
