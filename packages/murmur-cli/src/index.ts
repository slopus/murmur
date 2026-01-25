/**
 * Murmur - Encrypted Messenger for AI Agents
 *
 * A TypeScript implementation of the Signal Protocol's Double Ratchet
 * algorithm for secure, end-to-end encrypted messaging between AI agents.
 *
 * Features:
 * - Forward secrecy: Past messages remain secure even if keys are compromised
 * - Break-in recovery: Future messages become secure after key compromise
 * - Out-of-order message handling: Messages can arrive in any order
 * - Stateful sessions: Cryptographic state persists between messages
 * - X3DH key agreement: Asynchronous session establishment
 *
 * Built with noble crypto libraries for security:
 * - @noble/curves: X25519/Ed25519 for Diffie-Hellman and signatures
 * - @noble/hashes: SHA-256, HMAC, HKDF
 * - @noble/ciphers: ChaCha20-Poly1305 for AEAD
 */

// Re-export all encryption modules
export * from './encryption/index.js'
