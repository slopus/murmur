import { createRemoteJWKSet, jwtVerify } from "jose";

export interface AuthenticatedWorkOSIdentity {
    readonly userId: string;
}

export type AuthenticateWorkOSAccessToken = (
    accessToken: string,
) => Promise<AuthenticatedWorkOSIdentity>;

export function workOSIssuer(clientId: string): string {
    return `https://api.workos.com/user_management/${encodeURIComponent(clientId)}`;
}

/** Verify one WorkOS User Management access token against the application's public JWKS. */
export function createWorkOSAccessTokenVerifier(
    clientId: string,
    issuer?: string,
): AuthenticateWorkOSAccessToken {
    const expectedIssuer = issuer?.trim() || workOSIssuer(clientId);
    const jwks = createRemoteJWKSet(
        new URL(`https://api.workos.com/sso/jwks/${encodeURIComponent(clientId)}`),
        { timeoutDuration: 5_000 },
    );

    return async (accessToken) => {
        const { payload } = await jwtVerify(accessToken, jwks, {
            algorithms: ["RS256"],
            issuer: expectedIssuer,
            requiredClaims: ["exp", "iat", "sub", "client_id", "sid"],
        });
        if (
            payload.client_id !== clientId ||
            typeof payload.sub !== "string" ||
            typeof payload.sid !== "string"
        ) {
            throw new Error("Invalid WorkOS access token claims");
        }
        return { userId: payload.sub };
    };
}
