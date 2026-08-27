import { existsSync, readFileSync } from "node:fs";
import { WorkOS } from "@workos-inc/node";
import { describe, expect, test } from "vitest";
import {
    HttpRelaySessionProvider,
    MemoryMurmurStore,
    MurmurClient,
    generateIdentityKeyPair,
    type IdentityKeyPair,
} from "../sources/index.js";
import { decodeBase64Url, utf8Decode, utf8Encode } from "../sources/utils/index.js";

const CREDENTIALS_URL = new URL("../../../.context/workos-staging.json", import.meta.url);
const WORKOS_CLIENT_ID = "client_01KZD3XE4EW1AF1P6WTFHBPR4J";
const SESSION_ISSUER = "https://murmur-relay-staging.bulka-llc.workers.dev/v2/session";
const DIRECTORY_ISSUER = "https://murmur-relay-staging.bulka-llc.workers.dev/v2/directory-ticket";
const REQUEST_TIMEOUT_MILLISECONDS = 20_000;
const SYNCHRONIZE_ROUNDS = 12;

interface StagingCredentials {
    readonly workosApiKey: string;
}

function credentials(): StagingCredentials | undefined {
    if (!existsSync(CREDENTIALS_URL)) return undefined;
    const value = JSON.parse(readFileSync(CREDENTIALS_URL, "utf8")) as unknown;
    if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        typeof (value as Record<string, unknown>).workosApiKey !== "string" ||
        (value as Record<string, unknown>).workosApiKey === "" ||
        Object.keys(value).some((key) => key !== "workosApiKey")
    ) {
        throw new Error(".context/workos-staging.json must contain only workosApiKey");
    }
    return value as StagingCredentials;
}

const stagingCredentials = credentials();

function authenticatedFetch(accessToken: string): typeof fetch {
    return async (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set("authorization", `Bearer ${accessToken}`);
        return fetch(input, { ...init, headers });
    };
}

function openClient(identity: IdentityKeyPair, accessToken: string): Promise<MurmurClient> {
    return MurmurClient.open({
        identity,
        sessionProvider: new HttpRelaySessionProvider(SESSION_ISSUER, {
            fetch: authenticatedFetch(accessToken),
            requestTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
        }),
        store: new MemoryMurmurStore(),
        webSocket: {
            requestTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
            streamHeartbeatTimeoutMilliseconds: REQUEST_TIMEOUT_MILLISECONDS,
        },
    });
}

async function directoryTicket(accessToken: string): Promise<Uint8Array> {
    const response = await authenticatedFetch(accessToken)(DIRECTORY_ISSUER, { method: "POST" });
    if (!response.ok) throw new Error(`Directory ticket request failed (${response.status})`);
    const value = (await response.json()) as unknown;
    if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        (value as Record<string, unknown>).version !== 1 ||
        typeof (value as Record<string, unknown>).ticket !== "string"
    ) {
        throw new Error("Invalid directory ticket response");
    }
    return decodeBase64Url((value as { readonly ticket: string }).ticket);
}

async function settle(clients: readonly MurmurClient[]): Promise<void> {
    for (let round = 0; round < SYNCHRONIZE_ROUNDS; round += 1) {
        for (const client of clients) await client.synchronize({ waitMilliseconds: 0 });
    }
}

describe.runIf(stagingCredentials !== undefined)("WorkOS-authenticated Murmur staging", () => {
    test("creates two accounts, forms a group, and exchanges messages both ways", async () => {
        const workos = new WorkOS({
            apiKey: stagingCredentials!.workosApiKey,
            clientId: WORKOS_CLIENT_ID,
            maxRetries: 0,
            timeout: REQUEST_TIMEOUT_MILLISECONDS,
        });
        const suffix = `${Date.now()}-${crypto.randomUUID()}`;
        const password = `Murmur-${crypto.randomUUID()}-Aa1!`;
        const createdUserIds: string[] = [];
        let aliceClient: MurmurClient | undefined;
        let bobClient: MurmurClient | undefined;
        try {
            const aliceEmail = `murmur-alice-${suffix}@murmur-e2e.test`;
            const bobEmail = `murmur-bob-${suffix}@murmur-e2e.test`;
            const aliceUser = await workos.userManagement.createUser({
                email: aliceEmail,
                emailVerified: true,
                firstName: "Murmur Alice",
                password,
            });
            createdUserIds.push(aliceUser.id);
            const bobUser = await workos.userManagement.createUser({
                email: bobEmail,
                emailVerified: true,
                firstName: "Murmur Bob",
                password,
            });
            createdUserIds.push(bobUser.id);
            const aliceAuthentication = await workos.userManagement.authenticateWithPassword({
                clientId: WORKOS_CLIENT_ID,
                email: aliceEmail,
                password,
            });
            const bobAuthentication = await workos.userManagement.authenticateWithPassword({
                clientId: WORKOS_CLIENT_ID,
                email: bobEmail,
                password,
            });

            const aliceIdentity = generateIdentityKeyPair();
            const bobIdentity = generateIdentityKeyPair();
            aliceClient = await openClient(aliceIdentity, aliceAuthentication.accessToken);
            bobClient = await openClient(bobIdentity, bobAuthentication.accessToken);
            await settle([aliceClient, bobClient]);

            const claim = await aliceClient.claimAccount(
                bobIdentity.publicKey,
                await directoryTicket(aliceAuthentication.accessToken),
            );
            const group = await aliceClient.createSession({
                descriptor: utf8Encode("workos-staging-group"),
                members: [claim],
                sendPolicy: "everyone",
            });
            await settle([aliceClient, bobClient]);
            if ((await bobClient.session(group.id))?.status === "pending") {
                await bobClient.activateSession(group.id);
            }
            expect((await bobClient.session(group.id))?.status).toBe("active");

            const bobReceived: string[] = [];
            await aliceClient.send(group.id, utf8Encode("hello from alice"));
            for (let round = 0; round < SYNCHRONIZE_ROUNDS; round += 1) {
                await aliceClient.synchronize({ waitMilliseconds: 0 });
                await bobClient.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: (updates) => {
                            for (const update of updates)
                                bobReceived.push(utf8Decode(update.bytes));
                        },
                    },
                );
                if (bobReceived.includes("hello from alice")) break;
            }
            expect(bobReceived).toContain("hello from alice");

            const aliceReceived: string[] = [];
            await bobClient.send(group.id, utf8Encode("hello from bob"));
            for (let round = 0; round < SYNCHRONIZE_ROUNDS; round += 1) {
                await bobClient.synchronize({ waitMilliseconds: 0 });
                await aliceClient.synchronize(
                    { waitMilliseconds: 0 },
                    {
                        onUpdates: (updates) => {
                            for (const update of updates) {
                                aliceReceived.push(utf8Decode(update.bytes));
                            }
                        },
                    },
                );
                if (aliceReceived.includes("hello from bob")) break;
            }
            expect(aliceReceived).toContain("hello from bob");

            await aliceClient.deleteSession(group.id);
            await settle([aliceClient, bobClient]);
            await aliceClient.deleteAccount();
            await bobClient.deleteAccount();
        } finally {
            await aliceClient?.close();
            await bobClient?.close();
            for (const userId of createdUserIds.reverse()) {
                await workos.userManagement.deleteUser(userId).catch(() => undefined);
            }
        }
    }, 180_000);
});
