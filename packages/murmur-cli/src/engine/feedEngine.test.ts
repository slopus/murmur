import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createId } from '@paralleldrive/cuid2'
import { MurmurEngine } from './engine.js'
import { MockServer, createMockApi } from './mockServer.js'

describe('feed engine', () => {
    let tempDir: string
    let server: MockServer
    let alice: MurmurEngine
    let bob: MurmurEngine
    let carol: MurmurEngine

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), 'murmur-feed-engine-'))
        server = new MockServer()

        alice = new MurmurEngine(join(tempDir, 'alice.db'))
        bob = new MurmurEngine(join(tempDir, 'bob.db'))
        carol = new MurmurEngine(join(tempDir, 'carol.db'))

        ;(alice as any).api = createMockApi(server)
        ;(bob as any).api = createMockApi(server)
        ;(carol as any).api = createMockApi(server)
    })

    afterEach(() => {
        alice.close()
        bob.close()
        carol.close()
        rmSync(tempDir, { recursive: true, force: true })
    })

    it('creates a feed and decrypts timeline items across members', async () => {
        const aliceAccount = await alice.createAccount('Alice')
        const bobAccount = await bob.createAccount('Bob')

        const feed = await alice.createFeed('Close Friends', 'private notes')
        await alice.addFeedMembers(feed.feedId, [bobAccount.identityKey])
        const posted = await alice.postFeedItem(feed.feedId, 'hello feed', createId())

        expect(posted.text).toBe('hello feed')

        const timeline = await bob.fetchFeedTimeline()
        expect(timeline.items).toHaveLength(1)
        expect(timeline.items[0].feedId).toBe(feed.feedId)
        expect(timeline.items[0].text).toBe('hello feed')

        const ownedFeeds = await alice.getOwnedFeeds()
        expect(ownedFeeds).toEqual([
            expect.objectContaining({
                feedId: feed.feedId,
                ownerId: aliceAccount.identityKey,
                name: 'Close Friends',
                description: 'private notes',
                currentEpoch: 0,
                owned: true
            })
        ])
    })

    it('rotates feed keys when removing members', async () => {
        const bobAccount = await bob.createAccount('Bob')
        const carolAccount = await carol.createAccount('Carol')
        await alice.createAccount('Alice')

        const feed = await alice.createFeed('Rotation Test')
        await alice.addFeedMembers(feed.feedId, [bobAccount.identityKey, carolAccount.identityKey])
        await alice.postFeedItem(feed.feedId, 'epoch 0', createId())

        const carolInitial = await carol.fetchFeedTimeline()
        expect(carolInitial.items.map(item => item.text)).toEqual(['epoch 0'])

        await alice.removeFeedMembers(feed.feedId, [carolAccount.identityKey])
        await alice.postFeedItem(feed.feedId, 'epoch 1', createId())

        const bobTimeline = await bob.fetchFeedTimeline()
        expect(bobTimeline.items.map(item => item.text)).toEqual(['epoch 1', 'epoch 0'])

        const carolAfterRemoval = await carol.fetchFeedTimeline()
        expect(carolAfterRemoval.items).toEqual([])
    })
})
