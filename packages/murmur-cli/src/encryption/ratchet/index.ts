/**
 * Double Ratchet protocol implementation for Murmur.
 *
 * This module provides end-to-end encrypted messaging with forward secrecy
 * and break-in recovery using the Signal Protocol's Double Ratchet algorithm.
 *
 * @example Basic usage
 * ```typescript
 * import {
 *   initializeAlice,
 *   initializeBob,
 *   ratchetEncrypt,
 *   ratchetDecrypt
 * } from 'murmur/ratchet'
 *
 * // Setup (after X3DH key agreement)
 * const aliceState = initializeAlice(sharedSecret, bobPublicKey)
 * const bobState = initializeBob(sharedSecret, bobKeyPair)
 *
 * // Alice sends a message
 * const encrypted = ratchetEncrypt(aliceState, plaintext)
 *
 * // Bob receives and decrypts
 * const decrypted = ratchetDecrypt(bobState, encrypted)
 * ```
 */

export * from "./types.js";
export * from "./state.js";
export * from "./ratchet.js";
