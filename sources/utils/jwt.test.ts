import { describe, it, expect } from 'vitest';
import { generateToken, verifyToken } from './jwt';

describe('JWT utilities', () => {
    describe('generateToken and verifyToken', () => {
        it('should generate and verify a valid token', () => {
            const userId = 'test-user-id';
            const token = generateToken(userId);

            expect(token).toBeDefined();
            expect(typeof token).toBe('string');

            const payload = verifyToken(token);
            expect(payload).toBeDefined();
            expect(payload?.userId).toBe(userId);
        });

        it('should reject invalid token', () => {
            const payload = verifyToken('invalid-token');
            expect(payload).toBeNull();
        });

        it('should reject tampered token', () => {
            const userId = 'test-user-id';
            const token = generateToken(userId);

            // Tamper with the token
            const tamperedToken = token.slice(0, -5) + 'XXXXX';
            const payload = verifyToken(tamperedToken);
            expect(payload).toBeNull();
        });

        it('should include iat and exp claims', () => {
            const userId = 'test-user-id';
            const token = generateToken(userId);

            const payload = verifyToken(token);
            expect(payload?.iat).toBeDefined();
            expect(payload?.exp).toBeDefined();
            expect(payload?.exp).toBeGreaterThan(payload!.iat!);
        });
    });
});
