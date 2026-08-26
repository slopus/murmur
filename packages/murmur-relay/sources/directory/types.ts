/** Verified, persistence-safe authorization carried by one opaque claim ticket. */
export interface DirectoryTicketClaims {
    readonly issuer: string;
    readonly ticketId: Uint8Array;
    readonly expiresAt: number;
    readonly claimBudget: number;
}

/** Authentication-server seam used by the relay before any exact-account claim. */
export interface DirectoryTicketVerifier {
    verify(ticket: Uint8Array, now: number): DirectoryTicketClaims | Promise<DirectoryTicketClaims>;
}

/** Inputs for one local/test authentication-server ticket. */
export interface IssueDirectoryTicketOptions {
    readonly expiresAt: number;
    readonly claimBudget: number;
    readonly ticketId?: Uint8Array;
}

/** Construction options for the deterministic local/test ticket authority. */
export interface LocalDirectoryTicketIssuerOptions {
    readonly issuer?: string;
    readonly secretKey?: Uint8Array;
}
