#!/usr/bin/env tsx
/**
 * Generate a new seed for privacy-kit JWT signing
 * Run this once and add the keys to your .env file
 */

import * as privacyKit from 'privacy-kit';

async function generateKeys() {
    // Generate a random seed (32 bytes)
    const seed = privacyKit.encodeBase64(privacyKit.crypto.randomKey(32));

    // Create a generator to get the public key
    const generator = await privacyKit.createPersistentTokenGenerator({
        service: 'murmur-auth',
        seed,
    });

    const publicKey = privacyKit.encodeBase64(generator.publicKey);

    console.log('\n🔑 Generated Keys for privacy-kit JWT\n');
    console.log('Add these to your .env file:\n');
    console.log(`JWT_SEED=${seed}`);
    console.log(`JWT_PUBLIC_KEY=${publicKey}`);
    console.log('\nKeep the JWT_SEED secret! The JWT_PUBLIC_KEY can be shared.\n');
}

generateKeys().catch(console.error);
